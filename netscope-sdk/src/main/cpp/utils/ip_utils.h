#pragma once
#include <cstdint>
#include <netinet/in.h>

namespace netscope {

// sockaddr → IP string (IPv4 or IPv6); fills out_port if not null.
// Returns false if family is not AF_INET or AF_INET6.
bool sockaddr_to_ip(const struct sockaddr* addr, char* out_ip, size_t len, uint16_t* out_port);

} // namespace netscope
