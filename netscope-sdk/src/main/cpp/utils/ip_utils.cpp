#include "ip_utils.h"
#include <arpa/inet.h>
#include <cstring>

namespace netscope {

bool sockaddr_to_ip(const struct sockaddr* addr, char* out_ip, size_t len, uint16_t* out_port) {
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        if (!inet_ntop(AF_INET, &a4->sin_addr, out_ip, static_cast<socklen_t>(len))) return false;
        if (out_port) *out_port = ntohs(a4->sin_port);
        return true;
    }
    if (addr->sa_family == AF_INET6) {
        auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (!inet_ntop(AF_INET6, &a6->sin6_addr, out_ip, static_cast<socklen_t>(len))) return false;
        if (out_port) *out_port = ntohs(a6->sin6_port);
        return true;
    }
    return false;
}

} // namespace netscope
