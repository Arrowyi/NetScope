#include "hook_stubs.h"
#include "hook_manager.h"
#include "libc_funcs.h"
#include "../netscope_log.h"
#include "bytehook.h"

#include <array>
#include <atomic>
#include <mutex>

namespace netscope {

// ── Diagnostic post-hook trace ─────────────────────────────────────────────
//
// Called by bytehook AFTER each GOT slot write (one invocation per
// {caller_lib, symbol}). Only enabled when DEBUG_TRACE_HOOKS is set in
// hook_manager_debug_flags(), so the overhead is zero in production.
//
// For each write we get:
//   - caller_path_name:  which library's GOT was patched
//   - sym_name:          which libc symbol
//   - new_func:          NetScope's stub (should always match our proxy)
//   - prev_func:         the value that was in the GOT IMMEDIATELY before
//                        bytehook wrote new_func
//
// If prev_func != dlsym(RTLD_NEXT)-resolved real libc, someone else was
// already hooking this library → CONTESTED. That's the key signal for
// diagnosing the asdk.httpclient crash pattern.
static void post_hook_trace_cb(bytehook_stub_t /*task_stub*/, int status_code,
                               const char* caller_path_name, const char* sym_name,
                               void* new_func, void* prev_func, void* arg) {
    if (status_code != BYTEHOOK_STATUS_CODE_OK) {
        // bytehook couldn't patch this slot — usually benign (lib ignored
        // via bytehook_add_ignore, or already hooked with the same stub).
        LOGW("bytehook-trace: hook-fail lib=%s sym=%s status=%d",
             caller_path_name ? caller_path_name : "?",
             sym_name         ? sym_name         : "?",
             status_code);
        return;
    }

    void* expected_real_libc = arg;
    const bool contested = expected_real_libc && prev_func &&
                           prev_func != expected_real_libc &&
                           prev_func != new_func;  // re-hook of our own slot

    if (contested) {
        LOGW("bytehook-trace: CONTESTED lib=%s sym=%s prev=%p (!= real libc=%p) new=%p "
             "— another hooker was already active in this library",
             caller_path_name ? caller_path_name : "?",
             sym_name         ? sym_name         : "?",
             prev_func, expected_real_libc, new_func);
    } else {
        LOGI("bytehook-trace: lib=%s sym=%s prev=%p new=%p",
             caller_path_name ? caller_path_name : "?",
             sym_name         ? sym_name         : "?",
             prev_func, new_func);
    }
}

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

    const int dbg = hook_manager_debug_flags();

    // DEBUG_SKIP_HOOKS: diagnostic build that initialises bytehook but
    // installs zero stubs. Lets HMI verify whether crashes are caused by
    // our GOT writes vs. bytehook init itself (CFI disable, shadowhook
    // relocation). We still succeed the call so hook_manager_init walks
    // the same code paths; the status layer will surface DEGRADED with
    // a clear diagnostic reason.
    if (dbg & DEBUG_SKIP_HOOKS) {
        LOGW("hook_stubs: DEBUG_SKIP_HOOKS active — NOT registering '%s' (stub=%p)",
             sym, new_func);
        return 0;
    }

    // DEBUG_TRACE_HOOKS: wire a post-hook callback so every GOT write
    // logs { lib, sym, prev, new } and flags contested slots. We pass
    // the dlsym-resolved real libc pointer as `arg` so the callback
    // can decide contested vs. clean without allocating state.
    bytehook_hooked_t post_cb  = nullptr;
    void*             post_arg = nullptr;
    if (dbg & DEBUG_TRACE_HOOKS) {
        post_cb  = &post_hook_trace_cb;
        post_arg = get_real_libc_for(sym);
    }

    // callee_path_name = "libc.so" targets the symbol's defining library.
    // Bytehook walks every loaded caller's GOT/PLT and patches the slot
    // that resolves to libc.so's `sym`. Late-loaded callers are handled
    // automatically via bytehook's internal dlopen integration.
    bytehook_stub_t h = bytehook_hook_all(
        /*callee_path_name=*/"libc.so",
        /*sym_name=*/sym,
        /*new_func=*/new_func,
        /*hooked=*/post_cb,
        /*hooked_arg=*/post_arg);
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
