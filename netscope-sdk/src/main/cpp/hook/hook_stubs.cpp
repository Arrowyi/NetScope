#include "hook_stubs.h"
#include "../netscope_log.h"
#include "bytehook.h"

#include <array>
#include <mutex>

namespace netscope {

// We register at most ~16 stubs (connect, close, getaddrinfo, 8 send/recv
// variants, room for a few more). Fixed array avoids any allocator
// interaction on the audit hot path. The exact-match set here is the
// ONLY valid way to answer "is this pointer one of NetScope's stubs?"
// — see docs/HOOK_EVOLUTION.md §P4.
namespace {
constexpr size_t kMaxStubs = 32;

std::array<void*,           kMaxStubs> g_stubs{};    // proxy function pointers
std::array<bytehook_stub_t, kMaxStubs> g_handles{};  // bytehook unhook handles
size_t                                 g_stub_n = 0;
std::mutex                             g_stub_mtx;
} // namespace

// The `pathname_regex` parameter is kept in the signature only for source
// compatibility with the xhook-era callers (hook_connect, hook_dns, ...).
// bytehook_hook_all hooks the symbol in EVERY loaded library and
// automatically hooks new libraries as they're dlopen'd, so the old
// ".*\\.so$" regex would be a no-op anyway.
//
// `old_func` is also ignored: see libc_funcs.h — we deliberately do NOT
// rely on the hooker's "prev" pointer. Every proxy calls the real libc
// entry point directly via libc().<fn>(), avoiding chaining into any
// host-app or vendor hook that happened to be installed first.
int register_stub(const char* /*pathname_regex*/,
                  const char* sym,
                  void*       new_func,
                  void**      /*old_func*/) {
    if (!sym || !new_func) return -1;

    // callee_path_name = "libc.so" targets the symbol's defining library.
    // Bytehook walks every loaded caller's GOT/PLT and patches the slot
    // that resolves to libc.so's `sym`. Late-loaded callers are handled
    // automatically via bytehook's internal dlopen integration.
    bytehook_stub_t h = bytehook_hook_all(
        /*callee_path_name=*/"libc.so",
        /*sym_name=*/sym,
        /*new_func=*/new_func,
        /*hooked=*/nullptr,
        /*hooked_arg=*/nullptr);
    if (!h) {
        LOGE("hook_stubs: bytehook_hook_all('%s') failed — returned null stub",
             sym);
        return -1;
    }

    std::lock_guard<std::mutex> lk(g_stub_mtx);
    bool seen = false;
    for (size_t i = 0; i < g_stub_n; ++i) {
        if (g_stubs[i] == new_func) { seen = true; break; }
    }
    if (!seen) {
        if (g_stub_n < kMaxStubs) {
            g_stubs[g_stub_n]   = new_func;
            g_handles[g_stub_n] = h;
            g_stub_n++;
        } else {
            LOGW("hook_stubs: registry full (%zu); cannot track '%s' stub=%p",
                 kMaxStubs, sym, new_func);
        }
    }
    LOGI("hook_stubs: bytehook_hook_all('%s') stub=%p handle=%p",
         sym, new_func, h);
    return 0;
}

bool is_registered_stub(void* p) {
    if (!p) return false;
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    for (size_t i = 0; i < g_stub_n; ++i) {
        if (g_stubs[i] == p) return true;
    }
    return false;
}

size_t registered_stub_count() {
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    return g_stub_n;
}

size_t registered_stubs_snapshot(void** out, size_t cap) {
    if (!out || cap == 0) return 0;
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    size_t n = g_stub_n < cap ? g_stub_n : cap;
    for (size_t i = 0; i < n; ++i) out[i] = g_stubs[i];
    return n;
}

void unhook_all_stubs() {
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    for (size_t i = 0; i < g_stub_n; ++i) {
        if (g_handles[i]) {
            int r = bytehook_unhook(g_handles[i]);
            if (r != 0) {
                LOGW("hook_stubs: bytehook_unhook(%p) returned %d",
                     g_handles[i], r);
            }
            g_handles[i] = nullptr;
        }
        g_stubs[i] = nullptr;
    }
    g_stub_n = 0;
}

} // namespace netscope
