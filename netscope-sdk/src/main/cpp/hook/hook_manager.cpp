#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "hook_stubs.h"
#include "libc_funcs.h"
#include "got_audit.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <android/dlext.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <csignal>
#include <csetjmp>
#include <cerrno>
#include <mutex>
#include <set>
#include <string>

namespace netscope {

// ─── Runtime state ──────────────────────────────────────────────────────────

static std::atomic<bool>         g_paused{false};
static std::atomic<HookStatus>   g_status{HOOK_STATUS_NOT_INITIALIZED};
static std::mutex                g_report_mutex;
static HookReport                g_report{};  // guarded by g_report_mutex

static std::mutex                g_listener_mutex;
static StatusListener            g_listener = nullptr;
static void*                     g_listener_user = nullptr;

static std::atomic<bool>         g_refresh_in_progress{false};

static void* (*orig_dlopen)(const char*, int)                                         = nullptr;
static void* (*orig_android_dlopen_ext)(const char*, int, const android_dlextinfo*)   = nullptr;

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

// ─── SIGSEGV guard during refresh ───────────────────────────────────────────
//
// xhook writes to GOT pages via mprotect(). Rare vendor/RELRO layouts have
// caused segfaults inside refresh in the wild. We install a SIGSEGV handler
// that siglongjmp's out of the refresh window only — for all other threads
// and times it chains back to the host app's original handler (Android's
// signal_chain + tombstoned).

static thread_local sigjmp_buf     t_refresh_jmp;
static thread_local bool           t_in_refresh = false;
static struct sigaction            g_old_sigsegv{};
static std::atomic<bool>           g_handler_installed{false};

static void netscope_sigsegv(int sig, siginfo_t* info, void* ctx) {
    if (t_in_refresh) {
        t_in_refresh = false;
        siglongjmp(t_refresh_jmp, 1);
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
        LOGW("hook_manager: sigaction(SIGSEGV) failed errno=%d, no crash guard", errno);
        g_handler_installed.store(false);
    } else {
        LOGI("hook_manager: SIGSEGV guard installed, old handler=%p",
             (void*)g_old_sigsegv.sa_sigaction);
    }
}

// ─── APK-embedded .so detection ─────────────────────────────────────────────
//
// Background: when the host APK is built with android:extractNativeLibs="false",
// bionic's linker maps native libraries directly out of base.apk as a set of
// PT_LOAD segments. /proc/self/maps reports synthesized paths like
//   /data/app/<pkg>-<hash>/base.apk!/lib/arm64-v8a/libX.so
// xhook 1.2.0's ELF parser mis-computes GOT addresses for this layout on some
// OEM ROMs (HONOR Android 10 is a confirmed repro) — it writes our stub
// pointers into rw-p heap pages that sit NEAR, not AT, the intended GOT
// slot. A perfectly clean post-install audit results (slots_corrupt=0),
// because the audit scans the set of GOTs we *intended* to patch, not the
// set xhook *actually* wrote to. Minutes later, when the host app reads
// one of those clobbered heap words back as a vtable pointer, it crashes
// with pc == x8 in [anon:libc_malloc].
//
// We cannot fix xhook 1.2.0's internals (it's a prebuilt static library).
// The next-best thing is to refuse to touch APK-embedded libraries
// altogether. xhook_ignore(regex, nullptr) skips any library whose path
// matches the regex during refresh, which is exactly what we need.

// Returns the count of distinct APK-embedded libraries currently mapped.
static int count_apk_embedded_libs(std::set<std::string>* out_paths) {
    FILE* fp = std::fopen("/proc/self/maps", "re");
    if (!fp) return 0;
    std::set<std::string> seen;
    char line[512];
    while (std::fgets(line, sizeof(line), fp)) {
        // Each maps line ends with an optional path. We only need the path.
        char* bang = std::strstr(line, ".apk!/");
        if (!bang) continue;
        char* start = std::strrchr(line, ' ');
        if (!start) continue;
        ++start;
        char* end = std::strchr(start, '\n');
        if (end) *end = '\0';
        // Only count once per distinct library path.
        seen.emplace(start);
    }
    std::fclose(fp);
    if (out_paths) *out_paths = std::move(seen);
    return static_cast<int>(out_paths ? out_paths->size() : seen.size());
}

static bool path_is_apk_embedded(const char* p) {
    return p && std::strstr(p, ".apk!/") != nullptr;
}

// ─── dlopen hooks ───────────────────────────────────────────────────────────
// Cover libraries loaded after init. Guarded by SIGSEGV handler above.

static void refresh_hooks_for_new_lib(const char* filename) {
    // If the initial post-install audit already flipped us to FAILED we
    // MUST NOT call xhook_refresh again — every refresh on this ROM can
    // corrupt more heap memory (see audit logic in hook_manager_init).
    if (g_status.load() == HOOK_STATUS_FAILED) return;

    // Defense in depth: even though we register xhook_ignore(".apk!/...") at
    // init, also refuse to trigger a refresh when an APK-embedded library is
    // the cause of the refresh. This skips the entire xhook_refresh() traversal
    // for such dlopens, which is safer than relying on xhook's ignore pass.
    if (path_is_apk_embedded(filename)) {
        LOGD("hook_manager: '%s' is APK-embedded — skipping refresh to avoid "
             "xhook 1.2.0 GOT miscomputation",
             filename);
        return;
    }

    if (g_refresh_in_progress.exchange(true)) return;
    LOGD("hook_manager: '%s' loaded, refreshing GOT hooks",
         filename ? filename : "(null)");

    t_in_refresh = true;
    if (sigsetjmp(t_refresh_jmp, 1) == 0) {
        xhook_refresh(0);
    } else {
        LOGE("hook_manager: SIGSEGV during xhook_refresh for '%s' — flipping to DEGRADED",
             filename ? filename : "(null)");
        set_status(HOOK_STATUS_DEGRADED, "SIGSEGV during dlopen-triggered xhook_refresh");
    }
    t_in_refresh = false;
    g_refresh_in_progress.store(false);
}

static void* hook_dlopen(const char* filename, int flags) {
    void* handle = orig_dlopen ? orig_dlopen(filename, flags)
                               : (libc().dlopen ? libc().dlopen(filename, flags) : nullptr);
    if (handle) refresh_hooks_for_new_lib(filename);
    return handle;
}

static void* hook_android_dlopen_ext(const char* filename, int flags,
                                      const android_dlextinfo* info) {
    void* handle = orig_android_dlopen_ext
                   ? orig_android_dlopen_ext(filename, flags, info)
                   : nullptr;
    if (handle) refresh_hooks_for_new_lib(filename);
    return handle;
}

// ─── init / destroy ─────────────────────────────────────────────────────────

int hook_manager_init() {
    set_status(HOOK_STATUS_NOT_INITIALIZED);
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report = HookReport{};
    }

    // Don't patch our own PLT — calls from libnetscope.so go straight to libc.
    xhook_ignore("libnetscope\\.so$", nullptr);

    // Block APK-embedded .so files unconditionally. On some OEM ROMs
    // (confirmed: HONOR Android 10 + extractNativeLibs=false) xhook 1.2.0's
    // ELF parser mis-computes the GOT VA for the base.apk!/lib/... synthesized
    // paths, causing stub pointers to land in unrelated rw-p heap pages and
    // crashing the host app with pc == x8 in [anon:libc_malloc] minutes later,
    // usually on the first native HTTP call. We can't fix xhook here; the
    // only safe option is to refuse to touch these libraries.
    //
    // Regex covers both classic bionic syntax (base.apk!/lib/abi/libX.so)
    // and the rarer suffix-less variant.
    xhook_ignore(".*\\.apk!/.*\\.so$", nullptr);
    xhook_ignore(".*\\.apk$",          nullptr);

    // Log which libraries are being skipped so the field report is actionable.
    std::set<std::string> skipped_paths;
    int apk_embedded = count_apk_embedded_libs(&skipped_paths);
    if (apk_embedded > 0) {
        LOGW("hook_manager: detected %d APK-embedded .so file(s); xhook_ignore "
             "applied. Host traffic from these libraries will NOT be tracked. "
             "Integrator should set android:extractNativeLibs=\"true\" in "
             "AndroidManifest.xml for full coverage.", apk_embedded);
        // Cap log volume but surface a few sample paths.
        int dumped = 0;
        for (const auto& p : skipped_paths) {
            LOGW("hook_manager:   skipped: %s", p.c_str());
            if (++dumped >= 8) break;
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.apk_embedded_libs_skipped = apk_embedded;
    }

    // Resolve real libc entry points via dlsym. We call these directly from
    // every hook handler instead of xhook's `orig_*`, which avoids chaining
    // into any pre-existing third-party hook trampoline.
    int libc_ok = resolve_libc_funcs();
    const bool libc_complete = (libc_ok >= 11);  // 11 networking + 1 dlopen
    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.libc_resolved = libc_complete;
    }
    if (!libc().connect || !libc().send || !libc().recv || !libc().read) {
        set_status(HOOK_STATUS_FAILED,
                   "libc symbol resolution failed for one or more critical functions");
        return -1;
    }

    // Install SIGSEGV guard BEFORE xhook_refresh so we can recover if the
    // initial refresh hits a bad library.
    install_sigsegv_guard();

    // xhook 1.2.0 ships its own best-effort SIGSEGV handler around GOT
    // mprotect/write. It's cheap and independent from our own guard — turn
    // it on so at least xhook can skip problem libs before our handler
    // would see the signal.
    xhook_enable_sigsegv_protection(1);

    // Register hooks (patterns only; xhook_refresh below applies them).
    int fail_connect    = install_hook_connect();
    int fail_dns        = install_hook_dns();
    int fail_send_recv  = install_hook_send_recv();
    int fail_close      = install_hook_close();

    {
        std::lock_guard<std::mutex> lock(g_report_mutex);
        g_report.connect_ok    = (fail_connect   == 0);
        g_report.dns_ok        = (fail_dns       == 0);
        g_report.send_recv_ok  = (fail_send_recv == 0);
        g_report.close_ok      = (fail_close     == 0);
    }

    // dlopen hooks to cover runtime-loaded libraries.
    register_stub(".*\\.so$", "dlopen",
                  (void*)hook_dlopen, (void**)&orig_dlopen);
    register_stub(".*\\.so$", "android_dlopen_ext",
                  (void*)hook_android_dlopen_ext, (void**)&orig_android_dlopen_ext);

    // Apply all registered hooks. Guarded by SIGSEGV handler — if xhook
    // crashes on a weird lib we land in the else branch and roll back.
    int refresh_ret = 0;
    t_in_refresh = true;
    if (sigsetjmp(t_refresh_jmp, 1) == 0) {
        refresh_ret = xhook_refresh(0);
    } else {
        LOGE("hook_manager_init: SIGSEGV during xhook_refresh — rolling back");
        xhook_clear();
        t_in_refresh = false;
        set_status(HOOK_STATUS_FAILED,
                   "SIGSEGV during xhook_refresh (likely a vendor lib with incompatible GOT layout)");
        return -2;
    }
    t_in_refresh = false;
    if (refresh_ret != 0) {
        LOGE("hook_manager_init: xhook_refresh failed ret=%d", refresh_ret);
        char buf[128];
        std::snprintf(buf, sizeof(buf), "xhook_refresh returned %d", refresh_ret);
        set_status(HOOK_STATUS_FAILED, buf);
        return refresh_ret;
    }

    verify_hook_connect();
    verify_hook_dns();
    verify_hook_send_recv();
    verify_hook_close();

    // ── Post-install audit ─────────────────────────────────────────────────
    //
    // The authoritative question is: "For each .so that was supposed to be
    // patched, does its GOT slot for connect/send/recv/... now hold one of
    // our registered stub pointers, or does it point into some data page
    // that would crash on call?"
    //
    // We walk every loaded .so's PLT relocations ourselves via
    // dl_iterate_phdr and read the real current GOT values back:
    //   - audit_slots_hooked   value exactly matches a stub we passed to
    //                          xhook_register — correct
    //   - audit_slots_unhooked value still equals real libc — benign
    //                          (lib excluded or loaded too late)
    //   - audit_slots_chained  value is inside another library's .text —
    //                          another hooker got there first
    //   - audit_slots_corrupt  value is in rw-p data / unmapped memory —
    //                          xhook misrouted the write; will crash
    //
    // The heap scan (audit_heap_stub_hits) is advisory only. xhook's own
    // bookkeeping (xh_core_hook_info_t list) legitimately stores copies of
    // our stub pointers in [anon:libc_malloc]; the bionic signal-handler
    // table stores our SIGSEGV guard address; etc. Those matches are
    // expected, so we never roll back based on heap-scan results.
    //
    // Only audit_slots_corrupt > 0 triggers rollback+FAILED.
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
        // Undo whatever xhook wrote (including any wrong writes), then
        // clear our registrations so dlopen-driven refreshes stop.
        xhook_clear();
        t_in_refresh = true;
        if (sigsetjmp(t_refresh_jmp, 1) == 0) xhook_refresh(0);
        t_in_refresh = false;

        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "post-install audit: %s (corrupt_slots=%d)",
                      audit.first_detail[0] ? audit.first_detail
                                            : "GOT slot points to non-executable memory",
                      audit.slots_corrupt);
        set_status(HOOK_STATUS_FAILED, buf);
        return -3;
    }

    if (audit.anon_stub_hits > 0) {
        // Informational. These are legitimate references (xhook registry,
        // signal handler table, soinfo copies) — NOT a crash risk given
        // that the real GOT audit came up clean.
        LOGI("hook_manager_init: heap scan saw %d stub refs in bookkeeping "
             "structures (xhook registry / sigaction / soinfo); GOT is clean",
             audit.anon_stub_hits);
    }

    const int total_failures = fail_connect + fail_dns + fail_send_recv + fail_close;
    const bool hooks_ok = (total_failures == 0) && libc_complete && (audit.slots_to_our_stub > 0);

    if (hooks_ok && apk_embedded == 0) {
        set_status(HOOK_STATUS_ACTIVE);
        LOGI("hook_manager_init: ACTIVE (audit: %d/%d slots hooked, %d libc, %d chained)",
             audit.slots_to_our_stub, audit.slots_total,
             audit.slots_to_real_libc, audit.slots_to_other_text);
    } else if (hooks_ok && apk_embedded > 0) {
        // Hooks themselves installed cleanly, but we *chose* to skip some
        // APK-embedded libraries. Flag this as DEGRADED so the HMI can
        // explain the partial coverage to the user.
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "skipped %d APK-embedded .so file(s) to avoid xhook 1.2.0 "
                      "GOT miscomputation; set extractNativeLibs=\"true\" for "
                      "full coverage (audit hooked=%d/%d slots)",
                      apk_embedded,
                      audit.slots_to_our_stub, audit.slots_total);
        set_status(HOOK_STATUS_DEGRADED, buf);
        LOGW("hook_manager_init: DEGRADED — %s", buf);
    } else {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "partial hooks: connect=%s dns=%s send_recv=%s close=%s libc=%d/12 "
                      "audit slots=%d hooked=%d apk-embedded-skipped=%d",
                      fail_connect   ? "FAIL" : "ok",
                      fail_dns       ? "FAIL" : "ok",
                      fail_send_recv ? "FAIL" : "ok",
                      fail_close     ? "FAIL" : "ok",
                      libc_ok,
                      audit.slots_total, audit.slots_to_our_stub,
                      apk_embedded);
        set_status(HOOK_STATUS_DEGRADED, buf);
        LOGW("hook_manager_init: %s", buf);
    }
    return 0;
}

void hook_manager_destroy() {
    LOGI("hook_manager_destroy: clearing hooks");
    xhook_clear();
    t_in_refresh = true;
    if (sigsetjmp(t_refresh_jmp, 1) == 0) xhook_refresh(0);
    t_in_refresh = false;
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
