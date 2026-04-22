#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "../netscope_log.h"
#include "bytehook.h"
#include <atomic>

namespace netscope {

static std::atomic<bool> g_paused{false};

int hook_manager_init() {
    int ret = bytehook_init(BYTEHOOK_MODE_AUTOMATIC, false);
    if (ret != 0) {
        LOGE("hook_manager_init: bytehook_init failed ret=%d", ret);
        return ret;
    }
    LOGI("hook_manager_init: bytehook ready, installing hooks");
    install_hook_connect();
    install_hook_dns();
    install_hook_send_recv();
    install_hook_close();
    LOGI("hook_manager_init: all hooks installed");
    return 0;
}

void hook_manager_destroy() {
    LOGI("hook_manager_destroy: uninstalling hooks");
    uninstall_hook_connect();
    uninstall_hook_dns();
    uninstall_hook_send_recv();
    uninstall_hook_close();
    LOGI("hook_manager_destroy: done");
}

void hook_manager_set_paused(bool paused) {
    g_paused.store(paused);
    LOGI("hook_manager: %s", paused ? "paused" : "resumed");
}
bool hook_manager_is_paused() { return g_paused.load(); }

} // namespace netscope
