#pragma once
#include <cstddef>
#include <cstdint>

namespace netscope {

// Returns true and fills out_sni (null-terminated) if buf starts with a TLS ClientHello
// containing an SNI extension.
bool parse_tls_sni(const uint8_t* buf, size_t len, char* out_sni, size_t sni_max_len);

// Returns true and fills out_host (null-terminated) if buf starts with an HTTP request
// containing a Host header. Strips port suffix (":8080") if present.
bool parse_http_host(const uint8_t* buf, size_t len, char* out_host, size_t host_max_len);

} // namespace netscope
