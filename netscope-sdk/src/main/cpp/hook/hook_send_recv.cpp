// Hooks send/recv/write/read/writev/readv/sendto/recvfrom in ALL loaded libraries via GOT/PLT.
//
// WHY xhook (pure GOT patcher):
//   xhook_register(".*\\.so$", sym, ...) patches the GOT entry in every loaded .so
//   including libconscrypt_jni.so (Java HTTPS) and any NDK native library.
//   It uses mprotect() to temporarily make the GOT page writable, then restores it.
//   Zero mmap(PROT_EXEC), zero trampolines — W^X-safe on all Android versions.
//
// NO DOUBLE-COUNTING:
//   Each call site's GOT is patched exactly once. A send() from libconscrypt_jni.so
//   fires this hook via that library's GOT; a send() from libnative.so fires via its
//   own GOT. No call ever crosses two patched entries.
//
// DOMAIN RESOLUTION:
//   try_resolve_domain runs once per fd (first send). TLS SNI/HTTP Host extraction
//   works for plaintext NDK traffic. For Conscrypt (encrypted TLS) both parsers fail
//   gracefully and the domain falls back to the DNS cache set at connect() time.

#include "hook_send_recv.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../utils/tls_sni_parser.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdint>

namespace netscope {

static ssize_t (*orig_send)(int, const void*, size_t, int)                                      = nullptr;
static ssize_t (*orig_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = nullptr;
static ssize_t (*orig_write)(int, const void*, size_t)                                          = nullptr;
static ssize_t (*orig_writev)(int, const struct iovec*, int)                                    = nullptr;
static ssize_t (*orig_recv)(int, void*, size_t, int)                                            = nullptr;
static ssize_t (*orig_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*)          = nullptr;
static ssize_t (*orig_read)(int, void*, size_t)                                                 = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec*, int)                                     = nullptr;

static void try_resolve_domain(int fd, const void* buf, size_t len) {
    if (FlowTable::instance().is_first_send_done(fd)) return;
    FlowTable::instance().set_first_send_done(fd);

    char domain[256] = {};
    if (netscope::parse_tls_sni(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, true);
        LOGD("domain-resolve: fd=%d via SNI -> %s", fd, domain);
        return;
    }
    if (netscope::parse_http_host(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, false);
        LOGD("domain-resolve: fd=%d via HTTP Host -> %s", fd, domain);
        return;
    }
    FlowEntry e{};
    if (FlowTable::instance().get(fd, &e)) {
        if (e.domain[0])
            LOGD("domain-resolve: fd=%d no SNI/Host, using DNS cache -> %s", fd, e.domain);
        else
            LOGW("domain-resolve: fd=%d no SNI/Host and DNS cache miss, will use IP", fd);
    }
}

static ssize_t hook_send(int fd, const void* buf, size_t len, int flags) {
    if (!orig_send) return -1;
    ssize_t ret = orig_send(fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t dest_len) {
    if (!orig_sendto) return -1;
    ssize_t ret = orig_sendto(fd, buf, len, flags, dest, dest_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    if (!orig_write) return -1;
    ssize_t ret = orig_write(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    if (!orig_writev) return -1;
    ssize_t ret = orig_writev(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    if (!orig_recv) return -1;
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    if (!orig_recvfrom) return -1;
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src, src_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    if (!orig_read) return -1;
    ssize_t ret = orig_read(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    if (!orig_readv) return -1;
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

void install_hook_send_recv() {
    xhook_register(".*\\.so$", "send",     (void*)hook_send,     (void**)&orig_send);
    xhook_register(".*\\.so$", "sendto",   (void*)hook_sendto,   (void**)&orig_sendto);
    xhook_register(".*\\.so$", "write",    (void*)hook_write,    (void**)&orig_write);
    xhook_register(".*\\.so$", "writev",   (void*)hook_writev,   (void**)&orig_writev);
    xhook_register(".*\\.so$", "recv",     (void*)hook_recv,     (void**)&orig_recv);
    xhook_register(".*\\.so$", "recvfrom", (void*)hook_recvfrom, (void**)&orig_recvfrom);
    xhook_register(".*\\.so$", "read",     (void*)hook_read,     (void**)&orig_read);
    xhook_register(".*\\.so$", "readv",    (void*)hook_readv,    (void**)&orig_readv);
}

void uninstall_hook_send_recv() {}  // teardown handled centrally by xhook_clear in hook_manager_destroy

} // namespace netscope
