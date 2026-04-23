#pragma once
//
// Real libc function pointers resolved via dlsym(RTLD_NEXT) at init time.
//
// WHY: xhook saves the previous GOT value into `orig_*`, but the previous value
// may already be a third-party hook's trampoline (e.g., the host app has its
// own native HTTP stack that hooked connect/send/recv before us). Calling
// `orig_*` then lands inside someone else's trampoline, whose private state
// may be stale / freed, causing `pc == x8` crashes where x8 is a heap address.
//
// Bypassing `orig_*` by calling the dlsym-resolved libc symbol directly
// guarantees we always reach the real libc implementation and never chain
// into another hooker's trampoline. NetScope's hook remains registered in the
// target library's GOT, so we still observe traffic — we just don't call
// "whatever was there before" on the way out.

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>

namespace netscope {

// One field per symbol we intercept. A null pointer means dlsym failed,
// which propagates to HookStatus so the upper layer can report DEGRADED.
struct LibcFuncs {
    int     (*connect)      (int, const struct sockaddr*, socklen_t)                                   = nullptr;
    int     (*close)        (int)                                                                      = nullptr;
    int     (*getaddrinfo)  (const char*, const char*, const struct addrinfo*, struct addrinfo**)      = nullptr;
    ssize_t (*send)         (int, const void*, size_t, int)                                            = nullptr;
    ssize_t (*sendto)       (int, const void*, size_t, int, const struct sockaddr*, socklen_t)         = nullptr;
    ssize_t (*write)        (int, const void*, size_t)                                                 = nullptr;
    ssize_t (*writev)       (int, const struct iovec*, int)                                            = nullptr;
    ssize_t (*recv)         (int, void*, size_t, int)                                                  = nullptr;
    ssize_t (*recvfrom)     (int, void*, size_t, int, struct sockaddr*, socklen_t*)                    = nullptr;
    ssize_t (*read)         (int, void*, size_t)                                                       = nullptr;
    ssize_t (*readv)        (int, const struct iovec*, int)                                            = nullptr;
    void*   (*dlopen)       (const char*, int)                                                         = nullptr;
};

// Populate libc_funcs() using dlsym(RTLD_NEXT). Returns the number of
// symbols that resolved successfully; the caller can compare against the
// total count to decide ACTIVE vs DEGRADED. Safe to call multiple times
// (idempotent after first success).
int resolve_libc_funcs();

// Read-only accessor. Never returns nullptr; fields may be nullptr if dlsym
// failed (check before calling).
const LibcFuncs& libc();

} // namespace netscope
