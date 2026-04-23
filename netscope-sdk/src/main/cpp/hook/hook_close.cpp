#include "hook_close.h"
#include "hook_manager.h"
#include "libc_funcs.h"
#include "../core/flow_table.h"
#include "../core/stats_aggregator.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <unistd.h>
#include <cstring>

namespace netscope {

// See libc_funcs.h — call real libc directly instead of xhook's `orig_*`.

static int hook_close(int fd) {
    if (hook_manager_is_enabled() && FlowTable::instance().contains(fd)) {
        FlowEntry e{};
        if (FlowTable::instance().remove(fd, &e)) {
            const std::string domain(e.domain[0] ? e.domain : e.remote_ip);
            // Only the bytes that haven't been pushed to the aggregator yet. Long-
            // lived connections have already had earlier bytes reported by
            // FlowTable::flush_in_flight() on each interval boundary.
            uint64_t tx_delta = e.tx_bytes - e.tx_reported;
            uint64_t rx_delta = e.rx_bytes - e.rx_reported;
            LOGI("flow-end: fd=%d %s:%u domain=%s tx=%llu(+%llu) rx=%llu(+%llu)",
                 fd, e.remote_ip, e.remote_port, domain.c_str(),
                 (unsigned long long)e.tx_bytes,
                 (unsigned long long)tx_delta,
                 (unsigned long long)e.rx_bytes,
                 (unsigned long long)rx_delta);
            StatsAggregator::instance().flush(domain, tx_delta, rx_delta);
            StatsAggregator::instance().invokeFlowEndCallback(domain, e.tx_bytes, e.rx_bytes);
        }
    }
    return libc().close ? libc().close(fd) : close(fd);
}

int install_hook_close() {
    int ret = xhook_register(".*\\.so$", "close", (void*)hook_close, nullptr);
    if (ret != 0) LOGE("hook_close: xhook_register failed ret=%d", ret);
    return ret;
}

void verify_hook_close() {
    if (libc().close) LOGI("hook_close: libc.close=%p", (void*)libc().close);
    else              LOGE("hook_close: libc.close null — close pass-through disabled");
}

void uninstall_hook_close() {}

} // namespace netscope
