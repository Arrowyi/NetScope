#include "hook_connect.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../core/dns_cache.h"
#include "../utils/ip_utils.h"
#include "shadowhook.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <android/log.h>

#define LOG_TAG "NetScope"

namespace netscope {

static void* g_stub = nullptr;
static int (*orig_connect)(int, const struct sockaddr*, socklen_t) = nullptr;

static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int ret = orig_connect(sockfd, addr, addrlen);
    if (hook_manager_is_paused() || !addr) return ret;

    char ip[64] = {};
    uint16_t port = 0;
    if (!sockaddr_to_ip(addr, ip, sizeof(ip), &port)) return ret;

    std::string domain = DnsCache::instance().lookup(ip);
    FlowTable::instance().create(sockfd, ip, port, domain.c_str());
    return ret;
}

void install_hook_connect() {
    g_stub = shadowhook_hook_sym_name(
        "libc.so", "connect",
        reinterpret_cast<void*>(hook_connect),
        reinterpret_cast<void**>(&orig_connect));
}

void uninstall_hook_connect() {
    if (g_stub) { shadowhook_unhook(g_stub); g_stub = nullptr; }
}

} // namespace netscope
