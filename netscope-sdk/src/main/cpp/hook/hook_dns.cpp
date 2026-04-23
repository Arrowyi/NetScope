#include "hook_dns.h"
#include "hook_manager.h"
#include "libc_funcs.h"
#include "../core/dns_cache.h"
#include "../netscope_log.h"
#include "xhook.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace netscope {

// See libc_funcs.h — we don't use xhook's `orig_*` anymore. Call real libc
// directly so we never chain into another hooker's trampoline.

static int hook_getaddrinfo(const char* node, const char* service,
                             const struct addrinfo* hints, struct addrinfo** res) {
    auto real = libc().getaddrinfo;
    if (!real) return EAI_SYSTEM;
    int ret = real(node, service, hints, res);
    if (!hook_manager_is_enabled() || ret != 0 || !node || !res || !*res) return ret;

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

int install_hook_dns() {
    int ret = xhook_register(".*\\.so$", "getaddrinfo", (void*)hook_getaddrinfo, nullptr);
    if (ret != 0) LOGE("hook_dns: xhook_register failed ret=%d", ret);
    return ret;
}

void verify_hook_dns() {
    if (libc().getaddrinfo) LOGI("hook_dns: libc.getaddrinfo=%p", (void*)libc().getaddrinfo);
    else                    LOGE("hook_dns: libc.getaddrinfo null — DNS pass-through disabled");
}

void uninstall_hook_dns() {}

} // namespace netscope
