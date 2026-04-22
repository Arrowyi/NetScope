#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <atomic>

namespace netscope {

static std::atomic<bool> g_paused{false};

int hook_manager_init() {
    // Prevent patching our own PLT to avoid any re-entrant surprise.
    xhook_ignore("libnetscope\\.so$", nullptr);

    // Register all hook patterns (no-op until xhook_refresh).
    install_hook_connect();
    install_hook_dns();
    install_hook_send_recv();
    install_hook_close();

    // Single refresh scans all currently-loaded libraries and patches GOT entries.
    // No mmap(PROT_EXEC) involved — xhook only uses mprotect on existing GOT pages.
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
