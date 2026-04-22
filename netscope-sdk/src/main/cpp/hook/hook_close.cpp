#include "hook_close.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../core/stats_aggregator.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <unistd.h>
#include <cstring>

namespace netscope {

static int (*orig_close)(int) = nullptr;

static int hook_close(int fd) {
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
    return orig_close ? orig_close(fd) : close(fd);
}

void install_hook_close() {
    int ret = xhook_register(".*\\.so$", "close", (void*)hook_close, (void**)&orig_close);
    if (ret != 0) LOGE("hook_close: xhook_register failed ret=%d", ret);
}

void verify_hook_close() {
    if (orig_close) LOGI("hook_close: active orig=%p", (void*)orig_close);
    else            LOGE("hook_close: orig_close null — close() not hooked");
}

void uninstall_hook_close() {}

} // namespace netscope
