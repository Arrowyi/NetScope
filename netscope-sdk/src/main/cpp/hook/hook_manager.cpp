#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <android/dlext.h>
#include <atomic>

namespace netscope {

static std::atomic<bool> g_paused{false};

// ── dlopen coverage ──────────────────────────────────────────────────────────
// Libraries loaded after hook_manager_init() won't have their GOT patched by
// the initial xhook_refresh(). Hook dlopen / android_dlopen_ext so that every
// newly loaded .so immediately gets the same GOT patches applied.
//
// Re-entrancy guard: xhook_refresh itself calls dl_iterate_phdr + mprotect,
// neither of which triggers dlopen. The guard is a safety net for edge cases.

static std::atomic<bool> g_refresh_in_progress{false};

static void* (*orig_dlopen)(const char*, int)                                         = nullptr;
static void* (*orig_android_dlopen_ext)(const char*, int, const android_dlextinfo*)   = nullptr;

static void refresh_hooks_for_new_lib(const char* filename) {
    if (g_refresh_in_progress.exchange(true)) return;
    LOGD("hook_manager: '%s' loaded, refreshing GOT hooks",
         filename ? filename : "(null)");
    xhook_refresh(0);
    g_refresh_in_progress.store(false);
}

static void* hook_dlopen(const char* filename, int flags) {
    void* handle = orig_dlopen ? orig_dlopen(filename, flags) : nullptr;
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

// ─────────────────────────────────────────────────────────────────────────────

int hook_manager_init() {
    // Don't patch our own PLT — calls from libnetscope.so go straight to libc.
    xhook_ignore("libnetscope\\.so$", nullptr);

    // Traffic hooks (register patterns; applied by xhook_refresh below).
    install_hook_connect();
    install_hook_dns();
    install_hook_send_recv();
    install_hook_close();

    // dlopen hooks: cover libraries loaded at runtime after this init.
    xhook_register(".*\\.so$", "dlopen",
                   (void*)hook_dlopen, (void**)&orig_dlopen);
    xhook_register(".*\\.so$", "android_dlopen_ext",
                   (void*)hook_android_dlopen_ext, (void**)&orig_android_dlopen_ext);

    // Single synchronous refresh: scans all currently-loaded .so files and
    // patches their GOT entries. No mmap(PROT_EXEC) — xhook only uses mprotect
    // on the existing (already-executable) GOT data pages.
    int ret = xhook_refresh(0);
    if (ret != 0) LOGE("hook_manager_init: xhook_refresh failed ret=%d", ret);
    else          LOGI("hook_manager_init: all hooks installed");
    return ret;
}

void hook_manager_destroy() {
    LOGI("hook_manager_destroy: clearing hooks");
    xhook_clear();
    xhook_refresh(0);
    LOGI("hook_manager_destroy: done");
}

void hook_manager_set_paused(bool paused) {
    g_paused.store(paused);
    LOGI("hook_manager: %s", paused ? "paused" : "resumed");
}
bool hook_manager_is_paused() { return g_paused.load(); }

} // namespace netscope
