#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "hook_stubs.h"
#include "libc_funcs.h"
#include "got_audit.h"
#include "../netscope_log.h"
#include "bytehook.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <csetjmp>
#include <cerrno>
#include <mutex>

namespace netscope {

// ─── Runtime state ──────────────────────────────────────────────────────────

static std::atomic<bool>         g_paused{false};
static std::atomic<HookStatus>   g_status{HOOK_STATUS_NOT_INITIALIZED};
static std::mutex                g_report_mutex;
static HookReport                g_report{};  // guarded by g_report_mutex

static std::mutex                g_listener_mutex;
static StatusListener            g_listener = nullptr;
static void*                     g_listener_user = nullptr;

// Diagnostic bitfield. Read from register_stub() (to skip registration),
// init_bytehook_once() (to pass `debug=true` to bytehook), and the
// trace-hook post-callback (to decide whether to log).
static std::atomic<int>          g_debug_flags{DEBUG_NONE};

void hook_manager_set_debug_flags(int flags) {
    g_debug_flags.store(flags);
    if (flags) {
        LOGW("hook_manager: DEBUG FLAGS SET flags=0x%x — diagnostic build, "
             "NOT FOR PRODUCTION USE", flags);
    }
}

int hook_manager_debug_flags() {
    return g_debug_flags.load();
}

// ─── Status / listener plumbing ─────────────────────────────────────────────

static void notify_status_locked() {
    StatusListener cb = nullptr;
    void* user = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_listener_mutex);
        cb = g_listener;
        user = g_listener_user;
    }
    if (cb) {
        HookReport snapshot;
        {
            std::lock_guard<std::mutex> lock(g_report_mutex);
            snapshot = g_report;
        }
        cb(snapshot, user);
    }
}

static void set_status(HookStatus s, const char* reason = nullptr) {
    HookStatus prev = g_status.exchange(s);
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.status = s;
        if (reason) {
            std::strncpy(g_report.failure_reason, reason, sizeof(g_report.failure_reason) - 1);
            g_report.failure_reason[sizeof(g_report.failure_reason) - 1] = '\0';
        } else {
            g_report.failure_reason[0] = '\0';
        }
    }
    if (prev != s) {
        LOGI("hook_manager: status %d -> %d%s%s",
             (int)prev, (int)s,
             reason ? " reason=" : "",
             reason ? reason     : "");
        notify_status_locked();
    }
}

void hook_manager_set_status_listener(StatusListener cb, void* user) {
    std::lock_guard<std::mutex> lock(g_listener_mutex);
    g_listener = cb;
    g_listener_user = user;
}

HookReport hook_manager_report() {
    std::lock_guard<std::mutex> lock(g_report_mutex);
    return g_report;
}

// ─── SIGSEGV guard around hook install ──────────────────────────────────────
//
// bytehook 1.1.1 has its own internal safety net, but we still wrap the
// install phase in a belt-and-braces guard: if anything faults during the
// initial install we siglongjmp out and flip to FAILED rather than
// crashing the app. The guard is only active on the init thread, and only
// during the narrow init window — once install is done we restore the
// previous SIGSEGV handler.

static thread_local sigjmp_buf     t_install_jmp;
static thread_local bool           t_in_install = false;
static struct sigaction            g_old_sigsegv{};
static std::atomic<bool>           g_handler_installed{false};

static void netscope_sigsegv(int sig, siginfo_t* info, void* ctx) {
    if (t_in_install) {
        t_in_install = false;
        siglongjmp(t_install_jmp, 1);
    }
    // Not our problem — chain to whatever the app had before us.
    if (g_old_sigsegv.sa_flags & SA_SIGINFO) {
        if (g_old_sigsegv.sa_sigaction) {
            g_old_sigsegv.sa_sigaction(sig, info, ctx);
            return;
        }
    } else {
        if (g_old_sigsegv.sa_handler == SIG_IGN) return;
        if (g_old_sigsegv.sa_handler != SIG_DFL && g_old_sigsegv.sa_handler) {
            g_old_sigsegv.sa_handler(sig);
            return;
        }
    }
    // SIG_DFL: restore default and re-raise so the tombstone writer sees it.
    std::signal(SIGSEGV, SIG_DFL);
    std::raise(SIGSEGV);
}

static void install_sigsegv_guard() {
    if (g_handler_installed.exchange(true)) return;
    struct sigaction sa{};
    sa.sa_sigaction = netscope_sigsegv;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, &g_old_sigsegv) != 0) {
        LOGW("hook_manager: sigaction(SIGSEGV) failed errno=%d, no install guard", errno);
        g_handler_installed.store(false);
    } else {
        LOGI("hook_manager: SIGSEGV guard installed, old handler=%p",
             (void*)g_old_sigsegv.sa_sigaction);
    }
}

// ─── bytehook init ──────────────────────────────────────────────────────────
//
// We use MANUAL mode deliberately. See docs/HOOK_EVOLUTION.md §P8:
//
//   - AUTOMATIC mode pre-allocates a shared PROT_EXEC trampoline page so
//     BYTEHOOK_CALL_PREV() can chain into the previous function in a proxy.
//     Strict-W^X kernels (some HONOR ROMs, several IVI head-units) refuse
//     `mmap(PROT_EXEC)` and the process dies at init.
//   - MANUAL mode skips the trampoline. Every proxy in NetScope calls the
//     real libc entry point via `libc().<fn>()` (resolved through
//     dlsym(RTLD_NEXT) at init), so we never need BYTEHOOK_CALL_PREV.
//
// If bytehook_init still fails we surface the numeric status code verbatim
// in the failureReason string so the HMI side can tell W^X (execmod) from
// any other failure. In MANUAL mode the W^X smoking gun is INITERR_CFI
// (bh_cfi_disable_slowpath uses mprotect(PROT_WRITE) on other libs' .text
// which can be refused on execmod-strict kernels). INITERR_TRAMPO /
// INITERR_HUB indicate bytehook hit its AUTOMATIC-mode trampoline code
// path — that would be a regression on our side (we should always be in
// MANUAL), not a platform problem.

static const char* bytehook_init_status_name(int code) {
    switch (code) {
        case BYTEHOOK_STATUS_CODE_OK:                return "OK";
        case BYTEHOOK_STATUS_CODE_INITERR_INVALID_ARG: return "INITERR_INVALID_ARG";
        case BYTEHOOK_STATUS_CODE_INITERR_SYM:       return "INITERR_SYM";
        case BYTEHOOK_STATUS_CODE_INITERR_TASK:      return "INITERR_TASK";
        case BYTEHOOK_STATUS_CODE_INITERR_HOOK:      return "INITERR_HOOK";
        case BYTEHOOK_STATUS_CODE_INITERR_ELF:       return "INITERR_ELF";
        case BYTEHOOK_STATUS_CODE_INITERR_ELF_REFR:  return "INITERR_ELF_REFR";
        case BYTEHOOK_STATUS_CODE_INITERR_TRAMPO:    return "INITERR_TRAMPO (W^X?)";
        case BYTEHOOK_STATUS_CODE_INITERR_SIG:       return "INITERR_SIG";
        case BYTEHOOK_STATUS_CODE_INITERR_DLMTR:     return "INITERR_DLMTR";
        case BYTEHOOK_STATUS_CODE_INITERR_CFI:       return "INITERR_CFI";
        case BYTEHOOK_STATUS_CODE_INITERR_SAFE:      return "INITERR_SAFE";
        case BYTEHOOK_STATUS_CODE_INITERR_HUB:       return "INITERR_HUB (W^X?)";
        default:                                     return "unknown";
    }
}

static int init_bytehook_once() {
    static std::atomic<int>  s_done{0};    // 0=not tried, 1=ok, 2=failed
    static std::atomic<int>  s_last_rc{BYTEHOOK_STATUS_CODE_UNINIT};
    int prev = s_done.load();
    if (prev == 1) return BYTEHOOK_STATUS_CODE_OK;
    if (prev == 2) return s_last_rc.load();

    const bool bh_debug = (g_debug_flags.load() & DEBUG_TRACE_HOOKS) != 0;
    int rc = bytehook_init(BYTEHOOK_MODE_MANUAL, /*debug=*/bh_debug);
    s_last_rc.store(rc);
    s_done.store(rc == BYTEHOOK_STATUS_CODE_OK ? 1 : 2);
    LOGI("hook_manager: bytehook_init(MANUAL, debug=%s) = %d (%s), ver=%s",
         bh_debug ? "true" : "false",
         rc, bytehook_init_status_name(rc),
         bytehook_get_version() ? bytehook_get_version() : "?");
    // Recordable mode lets us dump every hook action on demand later via
    // bytehook_get_records(); paired with DEBUG_TRACE_HOOKS gives HMI a
    // post-mortem dump if the logcat stream is lossy.
    if (bh_debug) {
        bytehook_set_recordable(true);
    }
    return rc;
}

// ─── init / destroy ─────────────────────────────────────────────────────────

int hook_manager_init() {
    set_status(HOOK_STATUS_NOT_INITIALIZED);
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report = HookReport{};
    }

    // Resolve real libc entry points via dlsym(RTLD_NEXT). We call these
    // directly from every hook handler instead of chaining through the
    // hooker's "prev" — see docs/HOOK_EVOLUTION.md §P2.
    int libc_ok = resolve_libc_funcs();
    const bool libc_complete = (libc_ok == 11);  // 11 networking symbols; see libc_funcs.h
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.libc_resolved = libc_complete;
    }
    if (!libc().connect || !libc().send || !libc().recv || !libc().read) {
        set_status(HOOK_STATUS_FAILED,
                   "libc symbol resolution failed for one or more critical functions");
        return -1;
    }

    // Install SIGSEGV guard BEFORE bytehook_init so any early fault from a
    // pathological loaded library is survivable.
    install_sigsegv_guard();

    // Initialise bytehook. Strongly expected to succeed on non-W^X ROMs.
    int bhrc = init_bytehook_once();
    if (bhrc != BYTEHOOK_STATUS_CODE_OK) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "bytehook_init returned %d (%s) — check W^X policy / kernel mmap",
                      bhrc, bytehook_init_status_name(bhrc));
        set_status(HOOK_STATUS_FAILED, buf);
        return -2;
    }

    // Don't patch our own libraries' PLT — calls originating inside
    // libnetscope.so go to libc directly. Also ignore libbytehook.so so
    // bytehook never tries to hook itself.
    bytehook_add_ignore("libnetscope.so");
    bytehook_add_ignore("libbytehook.so");

    // DEBUG_SKIP_HOOKS: bytehook is fully initialised (including CFI
    // disable + shadowhook trampoline registration) but we deliberately
    // do not register any stubs. Use this to isolate whether init itself
    // is what destabilises a given app (e.g. asdk.httpclient on HONOR
    // AGM3-W09HN), separate from NetScope's GOT writes. Traffic is not
    // collected in this mode. See README.md "Diagnostic mode".
    if (g_debug_flags.load() & DEBUG_SKIP_HOOKS) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "diagnostic: DEBUG_SKIP_HOOKS — bytehook initialised "
                      "(rc=%d, %s), no stubs registered",
                      bhrc, bytehook_init_status_name(bhrc));
        set_status(HOOK_STATUS_DEGRADED, buf);
        LOGW("hook_manager_init: %s", buf);
        return 0;
    }

    // Register hooks. Each install_hook_*() ends up calling register_stub()
    // (hook_stubs.cpp), which in turn calls bytehook_hook_all(). Bytehook
    // applies each hook immediately and also arranges to re-apply it to
    // libraries that get dlopen'd later, so we don't need our own dlopen
    // interception anymore (unlike the xhook era).
    int fail_connect   = 0;
    int fail_dns       = 0;
    int fail_send_recv = 0;
    int fail_close     = 0;

    t_in_install = true;
    if (sigsetjmp(t_install_jmp, 1) == 0) {
        fail_connect   = install_hook_connect();
        fail_dns       = install_hook_dns();
        fail_send_recv = install_hook_send_recv();
        fail_close     = install_hook_close();
    } else {
        LOGE("hook_manager_init: SIGSEGV during install — rolling back");
        t_in_install = false;
        unhook_all_stubs();
        set_status(HOOK_STATUS_FAILED,
                   "SIGSEGV during bytehook_hook_all (possible W^X or vendor-lib GOT layout issue)");
        return -3;
    }
    t_in_install = false;

    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.connect_ok    = (fail_connect   == 0);
        g_report.dns_ok        = (fail_dns       == 0);
        g_report.send_recv_ok  = (fail_send_recv == 0);
        g_report.close_ok      = (fail_close     == 0);
        // Kept for HMI backwards compatibility. Bytehook handles
        // APK-embedded libraries correctly, so this is always 0 now.
        g_report.apk_embedded_libs_skipped = 0;
    }

    verify_hook_connect();
    verify_hook_dns();
    verify_hook_send_recv();
    verify_hook_close();

    // ── Post-install audit ─────────────────────────────────────────────────
    //
    // Same authoritative question as before, now for bytehook: for each .so
    // that was supposed to be patched, does its GOT slot for connect/send/
    // recv/... point to one of our registered stub pointers, or does it
    // point into some data page that would crash on call?
    //
    //   audit_slots_hooked    value exactly matches a stub we registered
    //                         — correct
    //   audit_slots_unhooked  value still equals real libc — benign (lib
    //                         excluded or loaded too late)
    //   audit_slots_chained   value is inside another library's .text —
    //                         another hooker got there first
    //   audit_slots_corrupt   value is in rw-p data / unmapped memory —
    //                         hooker misrouted the write; would crash
    //
    // heap_stub_hits is advisory only (see §P4 in HOOK_EVOLUTION).
    GotAuditResult audit = audit_got(/*scan_anon_heap=*/true);
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.audit_slots_total    = audit.slots_total;
        g_report.audit_slots_hooked   = audit.slots_to_our_stub;
        g_report.audit_slots_unhooked = audit.slots_to_real_libc;
        g_report.audit_slots_chained  = audit.slots_to_other_text;
        g_report.audit_slots_corrupt  = audit.slots_corrupt;
        g_report.audit_heap_stub_hits = audit.anon_stub_hits;
    }

    if (audit.slots_corrupt > 0) {
        LOGE("hook_manager_init: GOT audit found %d slots pointing to non-executable "
             "memory — rolling back. first=%s",
             audit.slots_corrupt,
             audit.first_detail[0] ? audit.first_detail : "(none)");
        unhook_all_stubs();
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "post-install audit: %s (corrupt_slots=%d)",
                      audit.first_detail[0] ? audit.first_detail
                                            : "GOT slot points to non-executable memory",
                      audit.slots_corrupt);
        set_status(HOOK_STATUS_FAILED, buf);
        return -4;
    }

    if (audit.anon_stub_hits > 0) {
        LOGI("hook_manager_init: heap scan saw %d stub refs in bookkeeping "
             "structures (hooker registry / sigaction / soinfo); GOT is clean",
             audit.anon_stub_hits);
    }

    const int total_failures = fail_connect + fail_dns + fail_send_recv + fail_close;
    const bool hooks_ok = (total_failures == 0) && libc_complete && (audit.slots_to_our_stub > 0);

    if (hooks_ok) {
        set_status(HOOK_STATUS_ACTIVE);
        LOGI("hook_manager_init: ACTIVE (audit: %d/%d slots hooked, %d libc, %d chained)",
             audit.slots_to_our_stub, audit.slots_total,
             audit.slots_to_real_libc, audit.slots_to_other_text);
    } else {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "partial hooks: connect=%s dns=%s send_recv=%s close=%s libc=%d/11 "
                      "audit slots=%d hooked=%d",
                      fail_connect   ? "FAIL" : "ok",
                      fail_dns       ? "FAIL" : "ok",
                      fail_send_recv ? "FAIL" : "ok",
                      fail_close     ? "FAIL" : "ok",
                      libc_ok,
                      audit.slots_total, audit.slots_to_our_stub);
        set_status(HOOK_STATUS_DEGRADED, buf);
        LOGW("hook_manager_init: %s", buf);
    }
    return 0;
}

void hook_manager_destroy() {
    LOGI("hook_manager_destroy: unhooking all stubs");
    unhook_all_stubs();
    set_status(HOOK_STATUS_NOT_INITIALIZED);
    LOGI("hook_manager_destroy: done");
}

void hook_manager_set_paused(bool paused) {
    g_paused.store(paused);
    LOGI("hook_manager: %s", paused ? "paused" : "resumed");
}

bool hook_manager_is_paused() { return g_paused.load(); }

bool hook_manager_is_enabled() {
    if (g_paused.load()) return false;
    auto s = g_status.load();
    return s == HOOK_STATUS_ACTIVE || s == HOOK_STATUS_DEGRADED;
}

} // namespace netscope
