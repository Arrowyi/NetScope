#include "socket_proxy.h"
#include "got_patcher.h"
#include "fd_table.h"

#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <android/log.h>

#define TAG  "NetScope_Proxy"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

/* ── Per-thread reentrancy guard ────────────────────────────────────────── */
/* Prevents infinite recursion when the real libc implementation calls back
 * into a symbol we have hooked. */
static __thread int tls_in_hook = 0;

#define GUARD_ENTER()  do { if (tls_in_hook) goto call_orig; tls_in_hook = 1; } while(0)
#define GUARD_EXIT()   do { tls_in_hook = 0; } while(0)

/* ── Original function pointers (filled by got_patcher_install) ─────────── */

static void* g_orig_connect  = NULL;
static void* g_orig_send     = NULL;
static void* g_orig_sendto   = NULL;
static void* g_orig_sendmsg  = NULL;
static void* g_orig_write    = NULL;
static void* g_orig_recv     = NULL;
static void* g_orig_recvfrom = NULL;
static void* g_orig_recvmsg  = NULL;
static void* g_orig_read     = NULL;
static void* g_orig_close    = NULL;

/* ── Helpers ────────────────────────────────────────────────────────────── */

/* Format a sockaddr into "ip:port" (IPv4) or "[ip]:port" (IPv6).
 * Only AF_INET and AF_INET6 are tracked; other families are ignored. */
static int format_addr(const struct sockaddr* sa, char* out, size_t out_sz) {
    if (!sa || !out || out_sz < 8) return 0;
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in* s4 = (const struct sockaddr_in*)sa;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof(ip));
        snprintf(out, out_sz, "%s:%d", ip, (int)ntohs(s4->sin_port));
        return 1;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6* s6 = (const struct sockaddr_in6*)sa;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &s6->sin6_addr, ip, sizeof(ip));
        snprintf(out, out_sz, "[%s]:%d", ip, (int)ntohs(s6->sin6_port));
        return 1;
    }
    return 0; /* UNIX sockets, etc. — not tracked */
}

/* ── Stub implementations ─────────────────────────────────────────────────
 * Each stub:
 *   1. Checks reentrancy guard (goto call_orig if already inside a hook).
 *   2. Performs accounting.
 *   3. Calls the real libc function via the saved pointer.
 * The goto idiom avoids nested function calls when in_hook is set.
 */

static int stub_connect(int fd, const struct sockaddr* addr, socklen_t addrlen) {
    typedef int (*fn_t)(int, const struct sockaddr*, socklen_t);
    GUARD_ENTER();
    {
        char remote[64] = {0};
        if (format_addr(addr, remote, sizeof(remote))) {
            fd_table_connect(fd, remote);
        }
    }
    GUARD_EXIT();
call_orig:
    return ((fn_t)g_orig_connect)(fd, addr, addrlen);
}

static ssize_t stub_send(int fd, const void* buf, size_t len, int flags) {
    typedef ssize_t (*fn_t)(int, const void*, size_t, int);
    ssize_t ret = ((fn_t)g_orig_send)(fd, buf, len, flags);
    GUARD_ENTER();
    if (ret > 0) fd_table_add_tx(fd, (int64_t)ret);
    GUARD_EXIT();
call_orig:
    return ret;
}

static ssize_t stub_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t alen) {
    typedef ssize_t (*fn_t)(int, const void*, size_t, int,
                             const struct sockaddr*, socklen_t);
    /* If dest is provided and fd not yet tracked, record the address.
     * This covers UDP sendto where connect() was never called. */
    GUARD_ENTER();
    {
        char remote[64] = {0};
        if (dest && format_addr(dest, remote, sizeof(remote))) {
            fd_table_connect(fd, remote); /* idempotent; safe to call again */
        }
    }
    GUARD_EXIT();
call_orig:;
    ssize_t ret = ((fn_t)g_orig_sendto)(fd, buf, len, flags, dest, alen);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_tx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_sendmsg(int fd, const struct msghdr* msg, int flags) {
    typedef ssize_t (*fn_t)(int, const struct msghdr*, int);
    ssize_t ret = ((fn_t)g_orig_sendmsg)(fd, msg, flags);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_tx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_write(int fd, const void* buf, size_t count) {
    typedef ssize_t (*fn_t)(int, const void*, size_t);
    ssize_t ret = ((fn_t)g_orig_write)(fd, buf, count);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_tx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_recv(int fd, void* buf, size_t len, int flags) {
    typedef ssize_t (*fn_t)(int, void*, size_t, int);
    ssize_t ret = ((fn_t)g_orig_recv)(fd, buf, len, flags);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_rx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* alen) {
    typedef ssize_t (*fn_t)(int, void*, size_t, int,
                             struct sockaddr*, socklen_t*);
    ssize_t ret = ((fn_t)g_orig_recvfrom)(fd, buf, len, flags, src, alen);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_rx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_recvmsg(int fd, struct msghdr* msg, int flags) {
    typedef ssize_t (*fn_t)(int, struct msghdr*, int);
    ssize_t ret = ((fn_t)g_orig_recvmsg)(fd, msg, flags);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_rx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static ssize_t stub_read(int fd, void* buf, size_t count) {
    typedef ssize_t (*fn_t)(int, void*, size_t);
    ssize_t ret = ((fn_t)g_orig_read)(fd, buf, count);
    if (ret > 0) {
        tls_in_hook = 1;
        fd_table_add_rx(fd, (int64_t)ret);
        tls_in_hook = 0;
    }
    return ret;
}

static int stub_close(int fd) {
    typedef int (*fn_t)(int);
    tls_in_hook = 1;
    fd_table_close(fd);
    tls_in_hook = 0;
    return ((fn_t)g_orig_close)(fd);
}

/* ── Hook table ─────────────────────────────────────────────────────────── */

static HookDesc g_hooks[] = {
    { "connect",   stub_connect,   &g_orig_connect  },
    { "send",      stub_send,      &g_orig_send     },
    { "sendto",    stub_sendto,    &g_orig_sendto   },
    { "sendmsg",   stub_sendmsg,   &g_orig_sendmsg  },
    { "write",     stub_write,     &g_orig_write    },
    { "recv",      stub_recv,      &g_orig_recv     },
    { "recvfrom",  stub_recvfrom,  &g_orig_recvfrom },
    { "recvmsg",   stub_recvmsg,   &g_orig_recvmsg  },
    { "read",      stub_read,      &g_orig_read     },
    { "close",     stub_close,     &g_orig_close    },
};
#define HOOK_COUNT ((int)(sizeof(g_hooks) / sizeof(g_hooks[0])))

/* ── Public API ─────────────────────────────────────────────────────────── */

int socket_proxy_install(void) {
    fd_table_init();
    int n = got_patcher_install(g_hooks, HOOK_COUNT);
    LOGI("socket_proxy_install: %d GOT entries patched", n);
    return n;
}

void socket_proxy_uninstall(void) {
    got_patcher_uninstall();
}
