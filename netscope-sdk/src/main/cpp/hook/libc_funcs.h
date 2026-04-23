#pragma once
//
// Real libc function pointers resolved via dlsym(RTLD_NEXT) at init time.
//
// WHY we don't use the hooker's "call-previous" mechanism (xhook's `orig_*`
// out-parameter, bytehook's `BYTEHOOK_CALL_PREV`): the previous GOT value
// might already be a third-party hook's trampoline. For example, the host
// app has its own native HTTP stack that hooked connect/send/recv before
// NetScope loaded. Chaining through "the value that was in the GOT before
// we patched it" lands inside someone else's trampoline, whose private
// state may be stale or freed, producing `pc == x8` crashes where x8 is
// a heap address.
//
// Bypassing the hooker's prev-chain entirely and calling the dlsym(RTLD_NEXT)
// resolved libc symbol directly guarantees we always reach the real libc
// implementation and never chain into another hooker's trampoline. NetScope's
// hook remains registered in the target library's GOT so we still observe
// traffic — we just don't call "whatever was there before" on the way out.
//
// Bonus: this is also why NetScope is W^X-safe under bytehook MANUAL mode.
// BYTEHOOK_CALL_PREV requires bytehook's hub trampoline, which in turn
// requires bh_trampo_alloc → mmap(PROT_EXEC). By never using CALL_PREV we
// keep that path unreachable. See docs/HOOK_EVOLUTION.md §P1.

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
