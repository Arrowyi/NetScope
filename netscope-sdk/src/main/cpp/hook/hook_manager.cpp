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

#include <dlfcn.h>
#include <unistd.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <csetjmp>
#include <cerrno>
#include <mutex>
#include <string>
#include <unordered_map>

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

// ─── bytehook_init side-effect diff logger ─────────────────────────────────
//
// Gated on DEBUG_TRACE_HOOKS (same switch as the per-write trace). When on,
// we snapshot the process state BEFORE calling bytehook_init() and AFTER,
// then log:
//
//   (a) New VMAs that appeared in /proc/self/maps (which .so got loaded,
//       which anon/exec pages got allocated).
//   (b) The first 32 bytes at a handful of well-known symbols NEEDED by
//       ART JNI dispatch + known shadowhook patch sites. Any byte that
//       changed between the two snapshots is spelled out in hex.
//
// The HONOR AGM3-W09HN + EMUI 11 / Magic UI 4.0 triage showed bytehook_init
// itself is the trigger (DEBUG_SKIP_HOOKS still crashes), so the before/
// after diff pinpoints which code bytes the bytehook-embedded shadowhook
// backend actually rewrites on this ROM.
//
// See HMI's CONSOLIDATED_ROOT_CAUSE_REPORT.md (2026-04-23) for the
// motivating crash-fingerprint analysis.

namespace {

struct ProbeTarget {
    const char* lib;    // for logging
    const char* sym;    // dlsym'd via RTLD_DEFAULT
    void*       addr;   // resolved once, cached
    uint8_t     before[32];
    bool        captured;
};

// Symbols picked specifically to cover the layers bytehook_init touches:
//   - libdl.so!__cfi_slowpath       – the documented shadowhook patch site
//                                     for bytehook's CFI-disable path
//   - libdl.so!dlopen               – bytehook hooks this to intercept
//                                     late-loaded libraries
//   - libdl.so!android_dlopen_ext   – modern variant of the above
//   - libc.so!abort / raise         – bh_safe_init uses shadowhook to
//                                     install signal handlers; any stray
//                                     inline hook here would show up
//   - libc.so!malloc / free         – hot ART JNI path; used to confirm
//                                     ART heap allocation isn't a victim
//   - libc.so!connect / send        – sanity, we should see no change here
static ProbeTarget g_probes[] = {
    {"libdl.so", "__cfi_slowpath",     nullptr, {}, false},
    {"libdl.so", "dlopen",             nullptr, {}, false},
    {"libdl.so", "android_dlopen_ext", nullptr, {}, false},
    {"libc.so",  "abort",              nullptr, {}, false},
    {"libc.so",  "raise",              nullptr, {}, false},
    {"libc.so",  "malloc",             nullptr, {}, false},
    {"libc.so",  "free",               nullptr, {}, false},
    {"libc.so",  "connect",            nullptr, {}, false},
    {"libc.so",  "send",               nullptr, {}, false},
    {"libc.so",  "pthread_create",     nullptr, {}, false},
};

static std::unordered_map<std::string, std::string> g_maps_before;

// Capture a 32-byte window starting at `addr` into `out`. Returns false
// if the page isn't readable (we don't SIGSEGV — we just skip).
static bool safe_copy32(const void* addr, uint8_t* out) {
    if (!addr) return false;
    // Best-effort: if the page isn't mapped readable, memcpy will fault.
    // We rely on /proc/self/maps having already classified addr's page
    // before reaching here; the dlsym'd symbol addresses are in .text of
    // public libs which are always r-xp. No fault expected in practice.
    std::memcpy(out, addr, 32);
    return true;
}

static void capture_probes_before() {
    for (auto& p : g_probes) {
        p.addr = dlsym(RTLD_DEFAULT, p.sym);
        if (!p.addr) continue;
        if (safe_copy32(p.addr, p.before)) p.captured = true;
    }
}

static void format_bytes32(const uint8_t* b, char* out, size_t cap) {
    // "aa bb cc dd ee ff ..." — 32 bytes → 96 chars + NUL
    size_t pos = 0;
    for (int i = 0; i < 32 && pos + 4 < cap; ++i) {
        pos += std::snprintf(out + pos, cap - pos, "%02x%s",
                             b[i], i == 31 ? "" : " ");
    }
    if (pos < cap) out[pos] = '\0';
}

static void log_probes_after_diff() {
    for (auto& p : g_probes) {
        if (!p.captured || !p.addr) {
            LOGI("init-diff: skip %s!%s (addr=%p captured=%d)",
                 p.lib, p.sym, p.addr, (int)p.captured);
            continue;
        }
        uint8_t after[32];
        if (!safe_copy32(p.addr, after)) {
            LOGW("init-diff: %s!%s unreadable after bytehook_init", p.lib, p.sym);
            continue;
        }
        if (std::memcmp(p.before, after, 32) == 0) {
            LOGI("init-diff: %s!%s @ %p UNCHANGED", p.lib, p.sym, p.addr);
        } else {
            char b_hex[128], a_hex[128];
            format_bytes32(p.before, b_hex, sizeof(b_hex));
            format_bytes32(after,    a_hex, sizeof(a_hex));
            LOGW("init-diff: %s!%s @ %p CHANGED",      p.lib, p.sym, p.addr);
            LOGW("init-diff:   before: %s",            b_hex);
            LOGW("init-diff:   after : %s",            a_hex);
        }
    }
}

// Snapshot /proc/self/maps into a map {start_addr_hex -> whole line}.
// We key on start address (stable across two calls within the same init
// window) so the diff can spot BOTH new mappings and perm changes on
// existing ones (e.g. r-xp → rwxp for a trampoline).
static void capture_maps_into(std::unordered_map<std::string, std::string>& out) {
    out.clear();
    FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return;
    char line[1024];
    while (std::fgets(line, sizeof(line), f)) {
        // Each line looks like "7a82310000-7a82320000 r-xp 00000000 ..."
        // Take everything up to the first '-' as the key.
        const char* dash = std::strchr(line, '-');
        if (!dash) continue;
        std::string key(line, dash - line);
        // Strip trailing newline on value for cleaner logs.
        size_t n = std::strlen(line);
        if (n && line[n - 1] == '\n') line[n - 1] = '\0';
        out.emplace(std::move(key), std::string(line));
    }
    std::fclose(f);
}

static void log_maps_diff() {
    std::unordered_map<std::string, std::string> after;
    capture_maps_into(after);

    // New (not in before)
    int new_count = 0;
    for (const auto& kv : after) {
        if (g_maps_before.find(kv.first) == g_maps_before.end()) {
            LOGW("init-diff: +vma %s", kv.second.c_str());
            ++new_count;
        }
    }
    // Changed perms (same key, different line)
    int changed_count = 0;
    for (const auto& kv : after) {
        auto it = g_maps_before.find(kv.first);
        if (it != g_maps_before.end() && it->second != kv.second) {
            LOGW("init-diff: ~vma before: %s", it->second.c_str());
            LOGW("init-diff: ~vma after : %s", kv.second.c_str());
            ++changed_count;
        }
    }
    LOGI("init-diff: maps summary: +%d new, %d changed (before=%zu after=%zu)",
         new_count, changed_count, g_maps_before.size(), after.size());
}

static void init_diff_snapshot_before() {
    capture_maps_into(g_maps_before);
    capture_probes_before();
    LOGI("init-diff: snapshot BEFORE bytehook_init — maps=%zu probes=%zu",
         g_maps_before.size(), sizeof(g_probes) / sizeof(g_probes[0]));
}

static void init_diff_log_after() {
    log_maps_diff();
    log_probes_after_diff();
    g_maps_before.clear();  // free memory after diffing
}

} // namespace

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

    const int  dbg      = g_debug_flags.load();
    const bool bh_debug = (dbg & DEBUG_TRACE_HOOKS) != 0;
    const bool diff_on  = (dbg & DEBUG_TRACE_HOOKS) != 0;  // reuse the trace switch

    if (diff_on) init_diff_snapshot_before();
    int rc = bytehook_init(BYTEHOOK_MODE_MANUAL, /*debug=*/bh_debug);
    if (diff_on) init_diff_log_after();

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

    // DEBUG_ULTRA_MINIMAL: hard stop — do NOT call bytehook_init at all.
    //
    // This is the most aggressive diagnostic: everything up to here is
    // pure dlsym(RTLD_NEXT) on libc.so (passive, no writes anywhere in
    // the process). If the app still crashes with this flag set, the
    // culprit is something loading libnetscope.so brought into the
    // process — NOT anything NetScope does at runtime. If the app stops
    // crashing, the culprit lives downstream of this line and is almost
    // certainly inside bytehook_init's shadowhook-backed CFI-disable /
    // safe-init paths.
    //
    // Added 2026-04-23 per HMI's HONOR AGM3-W09HN triage: DEBUG_SKIP_HOOKS
    // (which leaves bytehook_init intact but registers zero stubs) still
    // crashes with the same register fingerprint, so the trigger is
    // proven to be inside bytehook_init. This flag splits that further.
    if (g_debug_flags.load() & DEBUG_ULTRA_MINIMAL) {
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "diagnostic: DEBUG_ULTRA_MINIMAL — libc resolved "
                      "(%d/11) but bytehook_init NOT called",
                      libc_ok);
        set_status(HOOK_STATUS_DEGRADED, buf);
        LOGW("hook_manager_init: %s", buf);
        return 0;
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
