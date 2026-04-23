#include "flow_table.h"
#include "stats_aggregator.h"
#include "../netscope_log.h"
#include <cstring>
#include <string>
#include <vector>

namespace netscope {

FlowTable& FlowTable::instance() {
    static FlowTable inst;
    return inst;
}

void FlowTable::create(int fd, const char* ip, uint16_t port, const char* domain) {
    std::unique_lock lock(mutex_);
    FlowEntry e{};
    e.fd = fd;
    strncpy(e.remote_ip,   ip,     sizeof(e.remote_ip) - 1);
    strncpy(e.domain,      domain, sizeof(e.domain) - 1);
    e.remote_port = port;
    table_[fd] = e;
}

bool FlowTable::contains(int fd) {
    std::shared_lock lock(mutex_);
    return table_.count(fd) > 0;
}

void FlowTable::add_tx(int fd, uint64_t bytes) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.tx_bytes += bytes;
}

void FlowTable::add_rx(int fd, uint64_t bytes) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.rx_bytes += bytes;
}

void FlowTable::set_domain(int fd, const char* domain, bool from_sni) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it == table_.end()) return;
    if (it->second.domain_from_sni && !from_sni) return; // don't downgrade
    strncpy(it->second.domain, domain, sizeof(it->second.domain) - 1);
    it->second.domain_from_sni = from_sni;
}

void FlowTable::set_first_send_done(int fd) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.first_send_done = true;
}

bool FlowTable::is_first_send_done(int fd) {
    std::shared_lock lock(mutex_);
    auto it = table_.find(fd);
    return it != table_.end() && it->second.first_send_done;
}

bool FlowTable::remove(int fd, FlowEntry* out) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it == table_.end()) return false;
    if (out) *out = it->second;
    table_.erase(it);
    return true;
}

bool FlowTable::get(int fd, FlowEntry* out) {
    std::shared_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it == table_.end()) return false;
    if (out) *out = it->second;
    return true;
}

size_t FlowTable::flush_in_flight() {
    struct Delta { std::string domain; uint64_t tx; uint64_t rx; };
    std::vector<Delta> deltas;
    uint64_t total_tx = 0, total_rx = 0;
    {
        std::unique_lock lock(mutex_);
        deltas.reserve(table_.size());
        for (auto& [fd, e] : table_) {
            uint64_t dtx = e.tx_bytes - e.tx_reported;
            uint64_t drx = e.rx_bytes - e.rx_reported;
            if (dtx == 0 && drx == 0) continue;
            const char* key = e.domain[0] ? e.domain : e.remote_ip;
            if (!key || !key[0]) continue;
            deltas.push_back({std::string(key), dtx, drx});
            e.tx_reported = e.tx_bytes;
            e.rx_reported = e.rx_bytes;
            total_tx += dtx;
            total_rx += drx;
        }
    }
    for (auto& d : deltas) {
        StatsAggregator::instance().addBytes(d.domain, d.tx, d.rx);
    }
    if (!deltas.empty()) {
        LOGD("flow-table: flush_in_flight flows=%zu tx=%llu rx=%llu",
             deltas.size(),
             (unsigned long long)total_tx,
             (unsigned long long)total_rx);
    }
    return deltas.size();
}

} // namespace netscope
