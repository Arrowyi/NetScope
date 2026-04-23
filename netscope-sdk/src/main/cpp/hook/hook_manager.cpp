#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "libc_funcs.h"
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

// ─── dlopen hooks ───────────────────────────────────────────────────────────
// Cover libraries loaded after init. Guarded by SIGSEGV handler above.

static void refresh_hooks_for_new_lib(const char* filename) {
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
    xhook_register(".*\\.so$", "dlopen",
                   (void*)hook_dlopen, (void**)&orig_dlopen);
    xhook_register(".*\\.so$", "android_dlopen_ext",
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

    const int total_failures = fail_connect + fail_dns + fail_send_recv + fail_close;
    if (total_failures == 0 && libc_complete) {
        set_status(HOOK_STATUS_ACTIVE);
        LOGI("hook_manager_init: all hooks installed, status=ACTIVE");
    } else {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "partial hooks: connect=%s dns=%s send_recv=%s close=%s libc=%d/12",
                      fail_connect   ? "FAIL" : "ok",
                      fail_dns       ? "FAIL" : "ok",
                      fail_send_recv ? "FAIL" : "ok",
                      fail_close     ? "FAIL" : "ok",
                      libc_ok);
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
