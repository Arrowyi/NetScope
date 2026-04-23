#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <cstdint>
#include <functional>

namespace netscope {

struct DomainStatsC {
    char     domain[256];
    uint64_t tx_total;
    uint64_t rx_total;
    uint32_t count_total;
    uint64_t tx_curr;      // since last markIntervalBoundary
    uint64_t rx_curr;
    uint32_t count_curr;
    uint64_t tx_snap;      // last completed interval snapshot
    uint64_t rx_snap;
    uint32_t count_snap;
    int64_t  last_active_ms;
};

class StatsAggregator {
public:
    static StatsAggregator& instance();

    // Add bytes without incrementing the connection counter. Used by
    // FlowTable::flush_in_flight() to report incremental traffic for
    // connections that are still open.
    void addBytes(const std::string& domain, uint64_t tx, uint64_t rx);
    // Full flush at connection close: adds bytes AND increments connection count.
    void flush(const std::string& domain, uint64_t tx, uint64_t rx);
    void markIntervalBoundary();
    void clear();

    // Fills out with all tracked domains
    std::vector<DomainStatsC> getDomainStats();
    std::vector<DomainStatsC> getIntervalStats();  // last completed interval only

    // Called when a flow ends (for setOnFlowEnd callback)
    using FlowEndCallback = std::function<void(const DomainStatsC&)>;
    void setFlowEndCallback(FlowEndCallback cb);
    void invokeFlowEndCallback(const std::string& domain, uint64_t tx, uint64_t rx);

private:
    StatsAggregator() = default;
    static int64_t now_ms();

    struct Record {
        std::atomic<uint64_t> tx_total{0};
        std::atomic<uint64_t> rx_total{0};
        std::atomic<uint32_t> count_total{0};
        std::atomic<uint64_t> tx_curr{0};
        std::atomic<uint64_t> rx_curr{0};
        std::atomic<uint32_t> count_curr{0};
        std::atomic<int64_t>  last_active_ms{0};
    };

    struct Snap {
        uint64_t tx; uint64_t rx; uint32_t count;
    };

    // records_mutex_ guards insertions into records_ map; atomic fields within Record
    // are updated without the lock after the record exists
    std::shared_mutex records_mutex_;
    std::unordered_map<std::string, Record> records_;

    std::mutex snap_mutex_;
    std::unordered_map<std::string, Snap> snapshot_;

    std::mutex cb_mutex_;
    FlowEndCallback flow_end_cb_;
};

} // namespace netscope
