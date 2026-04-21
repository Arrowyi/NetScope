#include "dns_cache.h"
#include <chrono>

namespace netscope {

DnsCache& DnsCache::instance() {
    static DnsCache inst;
    return inst;
}

int64_t DnsCache::now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void DnsCache::store(const std::string& ip, const std::string& hostname) {
    if (ip.empty() || hostname.empty()) return;
    std::unique_lock lock(mutex_);
    cache_[ip] = {hostname, now_ms() + TTL_MS};
}

std::string DnsCache::lookup(const std::string& ip) {
    std::shared_lock lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) return {};
    if (it->second.expire_ms < now_ms()) return {};
    return it->second.hostname;
}

void DnsCache::clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
}

} // namespace netscope
