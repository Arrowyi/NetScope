// Hooks send/recv/write/read inside libconscrypt_jni.so to capture Java TLS byte counts.
//
// WHY THIS FILE EXISTS:
//   OkHttp and HttpsURLConnection route TLS I/O through Conscrypt (BoringSSL via JNI).
//   BoringSSL calls the kernel socket functions through libconscrypt_jni.so's own PLT,
//   not the main-process libc.so PLT that hook_send_recv.cpp patches. As a result,
//   connect()/close() still fire (FlowEntries are created/flushed correctly), but byte
//   counts for Java HTTPS traffic are 0 without these additional hooks.
//
// NO DOUBLE-COUNTING:
//   NDK C++ traffic goes through libc.so PLT only; Conscrypt traffic goes through
//   libconscrypt_jni.so PLT only. The two paths are mutually exclusive.
//
// DOMAIN RESOLUTION:
//   Not attempted here — at this layer the data is already encrypted TLS records.
//   The domain was already stored in the FlowEntry at connect() time via DNS cache.

#include "hook_conscrypt.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../netscope_log.h"
#include "shadowhook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

namespace netscope {

static void* g_stub_send     = nullptr;
static void* g_stub_sendto   = nullptr;
static void* g_stub_write    = nullptr;
static void* g_stub_writev   = nullptr;
static void* g_stub_recv     = nullptr;
static void* g_stub_recvfrom = nullptr;
static void* g_stub_read     = nullptr;
static void* g_stub_readv    = nullptr;

static ssize_t (*orig_send)(int, const void*, size_t, int)                                       = nullptr;
static ssize_t (*orig_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t)  = nullptr;
static ssize_t (*orig_write)(int, const void*, size_t)                                           = nullptr;
static ssize_t (*orig_writev)(int, const struct iovec*, int)                                     = nullptr;
static ssize_t (*orig_recv)(int, void*, size_t, int)                                             = nullptr;
static ssize_t (*orig_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*)           = nullptr;
static ssize_t (*orig_read)(int, void*, size_t)                                                  = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec*, int)                                      = nullptr;

static inline void count_tx(int fd, ssize_t ret) {
    if (!hook_manager_is_paused() && ret > 0 && FlowTable::instance().contains(fd))
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
}

static inline void count_rx(int fd, ssize_t ret) {
    if (!hook_manager_is_paused() && ret > 0 && FlowTable::instance().contains(fd))
        FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
}

static ssize_t hook_send(int fd, const void* buf, size_t len, int flags) {
    ssize_t ret = orig_send(fd, buf, len, flags);
    count_tx(fd, ret);
    return ret;
}

static ssize_t hook_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t dest_len) {
    ssize_t ret = orig_sendto(fd, buf, len, flags, dest, dest_len);
    count_tx(fd, ret);
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    ssize_t ret = orig_write(fd, buf, len);
    count_tx(fd, ret);
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_writev(fd, iov, iovcnt);
    count_tx(fd, ret);
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    ssize_t ret = orig_recv(fd, buf, len, flags);
    count_rx(fd, ret);
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src, src_len);
    count_rx(fd, ret);
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    ssize_t ret = orig_read(fd, buf, len);
    count_rx(fd, ret);
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    count_rx(fd, ret);
    return ret;
}

#define HOOK(stub, sym, fn, orig) \
    stub = shadowhook_hook_sym_name("libconscrypt_jni.so", sym, \
                                    reinterpret_cast<void*>(fn), \
                                    reinterpret_cast<void**>(orig))

void install_hook_conscrypt() {
    HOOK(g_stub_send,     "send",     hook_send,     &orig_send);
    HOOK(g_stub_sendto,   "sendto",   hook_sendto,   &orig_sendto);
    HOOK(g_stub_write,    "write",    hook_write,    &orig_write);
    HOOK(g_stub_writev,   "writev",   hook_writev,   &orig_writev);
    HOOK(g_stub_recv,     "recv",     hook_recv,     &orig_recv);
    HOOK(g_stub_recvfrom, "recvfrom", hook_recvfrom, &orig_recvfrom);
    HOOK(g_stub_read,     "read",     hook_read,     &orig_read);
    HOOK(g_stub_readv,    "readv",    hook_readv,    &orig_readv);

    LOGI("hook_conscrypt(libconscrypt_jni.so): send=%p sendto=%p write=%p writev=%p "
         "recv=%p recvfrom=%p read=%p readv=%p",
         g_stub_send, g_stub_sendto, g_stub_write, g_stub_writev,
         g_stub_recv, g_stub_recvfrom, g_stub_read, g_stub_readv);

    // All stubs null → libconscrypt_jni.so not loaded yet or PLT hooking unsupported.
    // Java HTTPS byte counts will remain 0; connect/close still work.
    if (!g_stub_send && !g_stub_write && !g_stub_recv && !g_stub_read)
        LOGW("hook_conscrypt: all stubs null — Java HTTPS byte counts will be 0 "
             "(libconscrypt_jni.so not loaded yet or PLT hooking unsupported)");
}

#undef HOOK

void uninstall_hook_conscrypt() {
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
