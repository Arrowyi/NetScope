#include "hook_close.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../core/stats_aggregator.h"
#include "../netscope_log.h"
#include "bytehook.h"
#include <unistd.h>
#include <cstring>

namespace netscope {

static bytehook_stub_t g_stub = nullptr;

static int hook_close(int fd) {
    BYTEHOOK_STACK_SCOPE();
    if (!hook_manager_is_paused() && FlowTable::instance().contains(fd)) {
        FlowEntry e{};
        if (FlowTable::instance().remove(fd, &e)) {
            const std::string domain(e.domain[0] ? e.domain : e.remote_ip);
            LOGI("flow-end: fd=%d %s:%u domain=%s tx=%llu rx=%llu",
                 fd, e.remote_ip, e.remote_port, domain.c_str(),
                 (unsigned long long)e.tx_bytes,
                 (unsigned long long)e.rx_bytes);
            StatsAggregator::instance().flush(domain, e.tx_bytes, e.rx_bytes);
            StatsAggregator::instance().invokeFlowEndCallback(domain, e.tx_bytes, e.rx_bytes);
        }
    }
    return BYTEHOOK_CALL_PREV(hook_close, fd);
}

void install_hook_close() {
    g_stub = bytehook_hook_all(nullptr, "close", (void*)hook_close, nullptr, nullptr);
    if (g_stub) LOGI("hook_close: installed");
    else        LOGE("hook_close: install failed");
}

void uninstall_hook_close() {
    if (g_stub) { bytehook_unhook(g_stub); g_stub = nullptr; }
}

} // namespace netscope
