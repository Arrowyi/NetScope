#pragma once
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

namespace netscope {

class DnsCache {
public:
    static DnsCache& instance();

    // Store hostname → all resolved IPs
    void store(const std::string& ip, const std::string& hostname);

    // Returns hostname for ip, or empty string on miss/expiry
    std::string lookup(const std::string& ip);

    void clear();

private:
    DnsCache() = default;

    static constexpr int64_t TTL_MS = 60'000;

    struct Entry {
        std::string hostname;
        int64_t     expire_ms;
    };

    std::unordered_map<std::string, Entry> cache_;
    std::shared_mutex mutex_;

    static int64_t now_ms();
};

} // namespace netscope
