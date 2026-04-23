#include "hook_connect.h"
#include "hook_manager.h"
#include "hook_stubs.h"
#include "libc_funcs.h"
#include "../core/flow_table.h"
#include "../core/dns_cache.h"
#include "../utils/ip_utils.h"
#include "../netscope_log.h"
#include <sys/socket.h>
#include <netinet/in.h>

namespace netscope {

// NOTE: We intentionally do NOT use the xhook-saved `orig_*` here. See
// libc_funcs.h for the rationale: calling xhook's `orig_*` can land inside
// another hooker's trampoline (e.g., the host app's own native HTTP stack)
// and crash. Instead we always call the dlsym-resolved real libc symbol.
// We still register with xhook so our hook is installed into every GOT.

static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    auto real = libc().connect;
    if (!real) return -1;
    int ret = real(sockfd, addr, addrlen);
    if (!hook_manager_is_enabled() || !addr) return ret;

    char ip[64] = {};
    uint16_t port = 0;
    if (!sockaddr_to_ip(addr, ip, sizeof(ip), &port)) return ret;

    std::string domain = DnsCache::instance().lookup(ip);
    FlowTable::instance().create(sockfd, ip, port, domain.c_str());
    LOGD("connect: fd=%d %s:%u domain=%s ret=%d",
         sockfd, ip, port, domain.empty() ? "(none)" : domain.c_str(), ret);
    return ret;
}

int install_hook_connect() {
    // `orig_*` out-param intentionally null — we don't rely on it.
    return register_stub(".*\\.so$", "connect", (void*)hook_connect, nullptr);
}

void verify_hook_connect() {
    if (libc().connect) LOGI("hook_connect: libc.connect=%p", (void*)libc().connect);
    else                LOGE("hook_connect: libc.connect null — connect pass-through disabled");
}

void uninstall_hook_connect() {}

} // namespace netscope
