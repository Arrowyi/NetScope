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
#include "libc_funcs.h"
#include "../core/flow_table.h"
#include "../utils/tls_sni_parser.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdint>

namespace netscope {

// See libc_funcs.h — all calls to the real libc go through libc().* which is
// resolved via dlsym at init time. This bypasses xhook's `orig_*` chain and
// prevents crashes when the host app has also hooked these symbols.

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
    auto real = libc().send;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len, flags);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t dest_len) {
    auto real = libc().sendto;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len, flags, dest, dest_len);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    auto real = libc().write;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    auto real = libc().writev;
    if (!real) return -1;
    ssize_t ret = real(fd, iov, iovcnt);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    auto real = libc().recv;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len, flags);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    auto real = libc().recvfrom;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len, flags, src, src_len);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    auto real = libc().read;
    if (!real) return -1;
    ssize_t ret = real(fd, buf, len);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    auto real = libc().readv;
    if (!real) return -1;
    ssize_t ret = real(fd, iov, iovcnt);
    if (!hook_manager_is_enabled() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

int install_hook_send_recv() {
    int failures = 0;
#define REG(sym, fn) \
    do { int r = xhook_register(".*\\.so$", sym, (void*)(fn), nullptr); \
         if (r != 0) { LOGE("hook_send_recv: register '%s' failed ret=%d", sym, r); ++failures; } } while(0)

    REG("send",     hook_send);
    REG("sendto",   hook_sendto);
    REG("write",    hook_write);
    REG("writev",   hook_writev);
    REG("recv",     hook_recv);
    REG("recvfrom", hook_recvfrom);
    REG("read",     hook_read);
    REG("readv",    hook_readv);
#undef REG
    return failures;
}

void verify_hook_send_recv() {
    const auto& l = libc();
    LOGI("hook_send_recv: libc.send=%p sendto=%p write=%p writev=%p "
         "recv=%p recvfrom=%p read=%p readv=%p",
         (void*)l.send,  (void*)l.sendto,
         (void*)l.write, (void*)l.writev,
         (void*)l.recv,  (void*)l.recvfrom,
         (void*)l.read,  (void*)l.readv);
    if (!l.send || !l.write || !l.recv || !l.read)
        LOGE("hook_send_recv: libc resolution incomplete for one or more symbols");
}

void uninstall_hook_send_recv() {}

} // namespace netscope
