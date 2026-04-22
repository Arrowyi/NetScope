// Hooks send/recv/write/read/writev/readv/sendto/recvfrom in ALL loaded libraries via PLT.
//
// WHY bytehook_hook_all:
//   bytehook_hook_all(NULL, sym, ...) patches the GOT/PLT entry for sym in every
//   loaded .so, including libconscrypt_jni.so (Java HTTPS) and any NDK native library.
//   New libraries loaded after init (dlopen) are automatically covered as well.
//   This replaces the previous two-file approach (hook_send_recv + hook_conscrypt).
//
// NO DOUBLE-COUNTING:
//   Each call site's PLT is patched exactly once. A call from libconscrypt_jni.so
//   fires the hook in libconscrypt's GOT; a call from libnative.so fires in its own
//   GOT. The same packet never crosses two patched PLT entries.
//
// DOMAIN RESOLUTION:
//   try_resolve_domain runs once per fd (first send). TLS SNI/HTTP Host extraction
//   works for plaintext NDK traffic; for Conscrypt (encrypted TLS) both parsers fail
//   gracefully and the domain falls back to the DNS cache set at connect() time.

#include "hook_send_recv.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../utils/tls_sni_parser.h"
#include "../netscope_log.h"
#include "bytehook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdint>

namespace netscope {

static bytehook_stub_t g_stub_send     = nullptr;
static bytehook_stub_t g_stub_sendto   = nullptr;
static bytehook_stub_t g_stub_write    = nullptr;
static bytehook_stub_t g_stub_writev   = nullptr;
static bytehook_stub_t g_stub_recv     = nullptr;
static bytehook_stub_t g_stub_recvfrom = nullptr;
static bytehook_stub_t g_stub_read     = nullptr;
static bytehook_stub_t g_stub_readv    = nullptr;

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
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_send, fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t dest_len) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_sendto, fd, buf, len, flags, dest, dest_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_write, fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_writev, fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_recv, fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_recvfrom, fd, buf, len, flags, src, src_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_read, fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    BYTEHOOK_STACK_SCOPE();
    ssize_t ret = BYTEHOOK_CALL_PREV(hook_readv, fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

void install_hook_send_recv() {
    g_stub_send     = bytehook_hook_all(nullptr, "send",     (void*)hook_send,     nullptr, nullptr);
    g_stub_sendto   = bytehook_hook_all(nullptr, "sendto",   (void*)hook_sendto,   nullptr, nullptr);
    g_stub_write    = bytehook_hook_all(nullptr, "write",    (void*)hook_write,    nullptr, nullptr);
    g_stub_writev   = bytehook_hook_all(nullptr, "writev",   (void*)hook_writev,   nullptr, nullptr);
    g_stub_recv     = bytehook_hook_all(nullptr, "recv",     (void*)hook_recv,     nullptr, nullptr);
    g_stub_recvfrom = bytehook_hook_all(nullptr, "recvfrom", (void*)hook_recvfrom, nullptr, nullptr);
    g_stub_read     = bytehook_hook_all(nullptr, "read",     (void*)hook_read,     nullptr, nullptr);
    g_stub_readv    = bytehook_hook_all(nullptr, "readv",    (void*)hook_readv,    nullptr, nullptr);

    LOGI("hook_send_recv(all libs): send=%p sendto=%p write=%p writev=%p "
         "recv=%p recvfrom=%p read=%p readv=%p",
         g_stub_send, g_stub_sendto, g_stub_write, g_stub_writev,
         g_stub_recv, g_stub_recvfrom, g_stub_read, g_stub_readv);

    if (!g_stub_send || !g_stub_write || !g_stub_recv || !g_stub_read)
        LOGE("hook_send_recv: one or more critical hooks failed");
}

void uninstall_hook_send_recv() {
    if (g_stub_send)     { bytehook_unhook(g_stub_send);     g_stub_send = nullptr; }
    if (g_stub_sendto)   { bytehook_unhook(g_stub_sendto);   g_stub_sendto = nullptr; }
    if (g_stub_write)    { bytehook_unhook(g_stub_write);    g_stub_write = nullptr; }
    if (g_stub_writev)   { bytehook_unhook(g_stub_writev);   g_stub_writev = nullptr; }
    if (g_stub_recv)     { bytehook_unhook(g_stub_recv);     g_stub_recv = nullptr; }
    if (g_stub_recvfrom) { bytehook_unhook(g_stub_recvfrom); g_stub_recvfrom = nullptr; }
    if (g_stub_read)     { bytehook_unhook(g_stub_read);     g_stub_read = nullptr; }
    if (g_stub_readv)    { bytehook_unhook(g_stub_readv);    g_stub_readv = nullptr; }
}

} // namespace netscope
