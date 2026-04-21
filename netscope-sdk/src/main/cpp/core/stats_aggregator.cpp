#include "stats_aggregator.h"
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

void StatsAggregator::flush(const std::string& domain, uint64_t tx, uint64_t rx) {
    if (domain.empty()) return;
    {
        // Fast path: record exists, update atomics without write lock
        std::shared_lock<std::shared_mutex> rlock(records_mutex_);
        auto it = records_.find(domain);
        if (it != records_.end()) {
            it->second.tx_total    += tx;
            it->second.rx_total    += rx;
            it->second.count_total += 1;
            it->second.tx_curr     += tx;
            it->second.rx_curr     += rx;
            it->second.count_curr  += 1;
            it->second.last_active_ms.store(now_ms());
            return;
        }
    }
    // Slow path: new domain
    std::unique_lock<std::shared_mutex> wlock(records_mutex_);
    // Re-check under write lock (another thread may have inserted between our two locks)
    auto it2 = records_.find(domain);
    if (it2 != records_.end()) {
        it2->second.tx_total    += tx;
        it2->second.rx_total    += rx;
        it2->second.count_total += 1;
        it2->second.tx_curr     += tx;
        it2->second.rx_curr     += rx;
        it2->second.count_curr  += 1;
        it2->second.last_active_ms.store(now_ms());
        return;
    }
    auto& r = records_[domain];
    r.tx_total    = tx;
    r.rx_total    = rx;
    r.count_total = 1;
    r.tx_curr     = tx;
    r.rx_curr     = rx;
    r.count_curr  = 1;
    r.last_active_ms = now_ms();
}

void StatsAggregator::markIntervalBoundary() {
    std::shared_lock<std::shared_mutex> rlock(records_mutex_);
    std::lock_guard<std::mutex> slock(snap_mutex_);
    snapshot_.clear();
    for (auto& [domain, r] : records_) {
        snapshot_[domain] = {
            r.tx_curr.exchange(0),
            r.rx_curr.exchange(0),
            r.count_curr.exchange(0)
        };
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
