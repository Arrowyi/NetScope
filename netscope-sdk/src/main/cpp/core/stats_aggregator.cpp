#include "stats_aggregator.h"
#include "../netscope_log.h"
#include <chrono>
#include <cstring>

namespace netscope {

StatsAggregator& StatsAggregator::instance() {
    static StatsAggregator inst;
    return inst;
}

int64_t StatsAggregator::now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void StatsAggregator::addBytes(const std::string& domain, uint64_t tx, uint64_t rx) {
    if (domain.empty() || (tx == 0 && rx == 0)) return;
    {
        // Fast path: record exists, update atomics under shared lock.
        std::shared_lock<std::shared_mutex> rlock(records_mutex_);
        auto it = records_.find(domain);
        if (it != records_.end()) {
            it->second.tx_total += tx;
            it->second.rx_total += rx;
            it->second.tx_curr  += tx;
            it->second.rx_curr  += rx;
            it->second.last_active_ms.store(now_ms());
            return;
        }
    }
    // Slow path: insert or locate under write lock, then add.
    std::unique_lock<std::shared_mutex> wlock(records_mutex_);
    auto& r = records_[domain];
    r.tx_total += tx;
    r.rx_total += rx;
    r.tx_curr  += tx;
    r.rx_curr  += rx;
    r.last_active_ms.store(now_ms());
}

void StatsAggregator::flush(const std::string& domain, uint64_t tx, uint64_t rx) {
    if (domain.empty()) return;
    // Always ensure the record exists so the connection count is recorded
    // even when a closed flow carried zero bytes.
    addBytes(domain, tx, rx);
    {
        std::shared_lock<std::shared_mutex> rlock(records_mutex_);
        auto it = records_.find(domain);
        if (it != records_.end()) {
            it->second.count_total += 1;
            it->second.count_curr  += 1;
            it->second.last_active_ms.store(now_ms());
            return;
        }
    }
    // tx == 0 && rx == 0: addBytes short-circuited, create an empty record now.
    std::unique_lock<std::shared_mutex> wlock(records_mutex_);
    auto& r = records_[domain];
    r.count_total += 1;
    r.count_curr  += 1;
    r.last_active_ms.store(now_ms());
}

void StatsAggregator::markIntervalBoundary() {
    size_t non_zero = 0;
    {
        std::shared_lock<std::shared_mutex> rlock(records_mutex_);
        std::lock_guard<std::mutex> slock(snap_mutex_);
        snapshot_.clear();
        for (auto& [domain, r] : records_) {
            uint64_t tx = r.tx_curr.exchange(0);
            uint64_t rx = r.rx_curr.exchange(0);
            uint32_t cc = r.count_curr.exchange(0);
            snapshot_[domain] = { tx, rx, cc };
            if (tx || rx) ++non_zero;
        }
        LOGD("stats: markIntervalBoundary records=%zu non_zero=%zu",
             records_.size(), non_zero);
    }
}

void StatsAggregator::clear() {
    std::unique_lock<std::shared_mutex> wlock(records_mutex_);
    records_.clear();
    std::lock_guard<std::mutex> slock(snap_mutex_);
    snapshot_.clear();
}

std::vector<DomainStatsC> StatsAggregator::getDomainStats() {
    std::shared_lock<std::shared_mutex> rlock(records_mutex_);
    std::vector<DomainStatsC> result;
    result.reserve(records_.size());
    for (auto& [domain, r] : records_) {
        DomainStatsC s{};
        strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
        s.tx_total      = r.tx_total.load();
        s.rx_total      = r.rx_total.load();
        s.count_total   = r.count_total.load();
        s.tx_curr       = r.tx_curr.load();
        s.rx_curr       = r.rx_curr.load();
        s.count_curr    = r.count_curr.load();
        s.last_active_ms = r.last_active_ms.load();
        result.push_back(s);
    }
    return result;
}

std::vector<DomainStatsC> StatsAggregator::getIntervalStats() {
    std::lock_guard<std::mutex> slock(snap_mutex_);
    std::vector<DomainStatsC> result;
    for (auto& [domain, snap] : snapshot_) {
        if (snap.tx == 0 && snap.rx == 0) continue;
        DomainStatsC s{};
        strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
        s.tx_snap    = snap.tx;
        s.rx_snap    = snap.rx;
        s.count_snap = snap.count;
        result.push_back(s);
    }
    return result;
}

void StatsAggregator::setFlowEndCallback(FlowEndCallback cb) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    flow_end_cb_ = std::move(cb);
}

void StatsAggregator::invokeFlowEndCallback(const std::string& domain, uint64_t tx, uint64_t rx) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    if (!flow_end_cb_) return;
    DomainStatsC s{};
    strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
    s.tx_curr = tx;
    s.rx_curr = rx;
    flow_end_cb_(s);
}

} // namespace netscope
