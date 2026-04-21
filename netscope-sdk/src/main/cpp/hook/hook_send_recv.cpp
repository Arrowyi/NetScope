#include "hook_send_recv.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../utils/tls_sni_parser.h"
#include "shadowhook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdint>

namespace netscope {

static void* g_stub_send = nullptr;
static void* g_stub_sendto = nullptr;
static void* g_stub_write = nullptr;
static void* g_stub_writev = nullptr;
static void* g_stub_recv = nullptr;
static void* g_stub_recvfrom = nullptr;
static void* g_stub_read = nullptr;
static void* g_stub_readv = nullptr;

static ssize_t (*orig_send)(int, const void*, size_t, int) = nullptr;
static ssize_t (*orig_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = nullptr;
static ssize_t (*orig_write)(int, const void*, size_t) = nullptr;
static ssize_t (*orig_writev)(int, const struct iovec*, int) = nullptr;
static ssize_t (*orig_recv)(int, void*, size_t, int) = nullptr;
static ssize_t (*orig_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec*, int) = nullptr;

static void try_resolve_domain(int fd, const void* buf, size_t len) {
    if (FlowTable::instance().is_first_send_done(fd)) return;
    FlowTable::instance().set_first_send_done(fd);

    char domain[256] = {};
    if (netscope::parse_tls_sni(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, true);
        return;
    }
    if (netscope::parse_http_host(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, false);
    }
}

static ssize_t hook_send(int fd, const void* buf, size_t len, int flags) {
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
    ssize_t ret = orig_sendto(fd, buf, len, flags, dest, dest_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    ssize_t ret = orig_write(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_writev(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        // SNI/Host extraction skipped for writev: iov is a scatter buffer,
        // not a contiguous packet. Domain should be set via connect (DNS) or send/write.
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src, src_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    ssize_t ret = orig_read(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

#define HOOK(stub, lib, sym, fn, orig) \
    stub = shadowhook_hook_sym_name(lib, sym, reinterpret_cast<void*>(fn), reinterpret_cast<void**>(orig))

void install_hook_send_recv() {
    HOOK(g_stub_send,     "libc.so", "send",     hook_send,     &orig_send);
    HOOK(g_stub_sendto,   "libc.so", "sendto",   hook_sendto,   &orig_sendto);
    HOOK(g_stub_write,    "libc.so", "write",    hook_write,    &orig_write);
    HOOK(g_stub_writev,   "libc.so", "writev",   hook_writev,   &orig_writev);
    HOOK(g_stub_recv,     "libc.so", "recv",     hook_recv,     &orig_recv);
    HOOK(g_stub_recvfrom, "libc.so", "recvfrom", hook_recvfrom, &orig_recvfrom);
    HOOK(g_stub_read,     "libc.so", "read",     hook_read,     &orig_read);
    HOOK(g_stub_readv,    "libc.so", "readv",    hook_readv,    &orig_readv);
}

void uninstall_hook_send_recv() {
    if (g_stub_send)     { shadowhook_unhook(g_stub_send);     g_stub_send = nullptr; }
    if (g_stub_sendto)   { shadowhook_unhook(g_stub_sendto);   g_stub_sendto = nullptr; }
    if (g_stub_write)    { shadowhook_unhook(g_stub_write);    g_stub_write = nullptr; }
    if (g_stub_writev)   { shadowhook_unhook(g_stub_writev);   g_stub_writev = nullptr; }
    if (g_stub_recv)     { shadowhook_unhook(g_stub_recv);     g_stub_recv = nullptr; }
    if (g_stub_recvfrom) { shadowhook_unhook(g_stub_recvfrom); g_stub_recvfrom = nullptr; }
    if (g_stub_read)     { shadowhook_unhook(g_stub_read);     g_stub_read = nullptr; }
    if (g_stub_readv)    { shadowhook_unhook(g_stub_readv);    g_stub_readv = nullptr; }
}

} // namespace netscope
