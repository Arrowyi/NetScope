#include "hook_dns.h"
#include "hook_manager.h"
#include "../core/dns_cache.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace netscope {

static int (*orig_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = nullptr;

static int hook_getaddrinfo(const char* node, const char* service,
                             const struct addrinfo* hints, struct addrinfo** res) {
    if (!orig_getaddrinfo) return -1;
    int ret = orig_getaddrinfo(node, service, hints, res);
    if (hook_manager_is_paused() || ret != 0 || !node || !res || !*res) return ret;

    int stored = 0;
    for (struct addrinfo* ai = *res; ai != nullptr; ai = ai->ai_next) {
        char ip[64] = {};
        if (ai->ai_family == AF_INET) {
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, ip, sizeof(ip));
        } else if (ai->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, ip, sizeof(ip));
        }
        if (ip[0] != '\0') {
            DnsCache::instance().store(ip, node);
            LOGD("dns: %s -> %s", node, ip);
            ++stored;
        }
    }
    if (stored == 0) LOGW("dns: getaddrinfo(%s) succeeded but no usable addresses", node);
    return ret;
}

void install_hook_dns() {
    xhook_register(".*\\.so$", "getaddrinfo", (void*)hook_getaddrinfo, (void**)&orig_getaddrinfo);
}

void uninstall_hook_dns() {}

} // namespace netscope
