#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "shadowhook.h"
#include <atomic>
#include <android/log.h>

#define LOG_TAG "NetScope"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace netscope {

static std::atomic<bool> g_paused{false};

int hook_manager_init() {
    int ret = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
    if (ret != 0) {
        LOGE("shadowhook_init failed: %d", ret);
        return ret;
    }
    install_hook_connect();
    install_hook_dns();
    install_hook_send_recv();
    install_hook_close();
    return 0;
}

void hook_manager_destroy() {
    uninstall_hook_connect();
    uninstall_hook_dns();
    uninstall_hook_send_recv();
    uninstall_hook_close();
}

void hook_manager_set_paused(bool paused) { g_paused.store(paused); }
bool hook_manager_is_paused()             { return g_paused.load(); }

} // namespace netscope
