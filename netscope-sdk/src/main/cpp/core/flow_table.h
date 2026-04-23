#pragma once
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

namespace netscope {

struct FlowEntry {
    int      fd;
    char     remote_ip[64];
    uint16_t remote_port;
    char     domain[256];
    uint64_t tx_bytes        = 0;
    uint64_t rx_bytes        = 0;
    // Bytes already pushed to StatsAggregator. Used to compute the delta on each
    // interval boundary (and on close) so long-lived connections can be reported
    // incrementally without double-counting.
    uint64_t tx_reported     = 0;
    uint64_t rx_reported     = 0;
    bool     domain_from_sni = false;  // SNI/Host already resolved → skip DNS override
    bool     first_send_done = false;
};

class FlowTable {
public:
    static FlowTable& instance();

    void   create(int fd, const char* ip, uint16_t port, const char* domain);
    bool   contains(int fd);
    void   add_tx(int fd, uint64_t bytes);
    void   add_rx(int fd, uint64_t bytes);
    // Update domain only if not yet resolved via SNI/Host
    void   set_domain(int fd, const char* domain, bool from_sni);
    void   set_first_send_done(int fd);
    bool   is_first_send_done(int fd);
    // Remove and return entry (for flush on close)
    bool   remove(int fd, FlowEntry* out);
    // Read-only peek (returns false if fd not found)
    bool   get(int fd, FlowEntry* out);
    // Push the per-flow delta (tx_bytes - tx_reported, rx_bytes - rx_reported) into
    // StatsAggregator for every active flow, then advance tx_reported/rx_reported to
    // the current totals. Enables long-lived connections to show up in reports without
    // waiting for close(). Returns the number of flows that contributed data.
    size_t flush_in_flight();

private:
    FlowTable() = default;
    std::unordered_map<int, FlowEntry> table_;
    std::shared_mutex mutex_;
};

} // namespace netscope
