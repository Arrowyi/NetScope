#include "tls_sni_parser.h"
#include <algorithm>
#include <cstring>

namespace netscope {

bool parse_tls_sni(const uint8_t* buf, size_t len, char* out_sni, size_t sni_max_len) {
    // Minimum: 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random) = 43
    if (len < 43) return false;
    if (buf[0] != 0x16)  return false;  // Content-Type: Handshake
    if (buf[5] != 0x01)  return false;  // HandshakeType: ClientHello

    size_t pos = 43;  // past fixed-length fields up through Random

    // Session ID
    if (pos >= len) return false;
    uint8_t sid_len = buf[pos++];
    if (pos + sid_len > len) return false;
    pos += sid_len;

    // Cipher Suites
    if (pos + 2 > len) return false;
    uint16_t cs_len = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    if (pos + cs_len > len) return false;
    pos += cs_len;

    // Compression Methods
    if (pos + 1 > len) return false;
    uint8_t cm_len = buf[pos++];
    if (pos + cm_len > len) return false;
    pos += cm_len;

    // Extensions length
    if (pos + 2 > len) return false;
    uint16_t exts_len = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    size_t exts_end = pos + exts_len;

    while (pos + 4 <= exts_end && pos + 4 <= len) {
        uint16_t ext_type = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
        uint16_t ext_len  = (static_cast<uint16_t>(buf[pos + 2]) << 8) | buf[pos + 3];
        pos += 4;

        if (ext_type == 0x0000) {  // SNI extension
            // server_name_list_length(2) + name_type(1) + name_length(2) + name
            if (pos + 5 > len) return false;
            uint16_t name_len = (static_cast<uint16_t>(buf[pos + 3]) << 8) | buf[pos + 4];
            pos += 5;
            if (pos + name_len > len) return false;
            size_t copy_len = std::min(static_cast<size_t>(name_len), sni_max_len - 1);
            memcpy(out_sni, buf + pos, copy_len);
            out_sni[copy_len] = '\0';
            return copy_len > 0;
        }
        if (pos + ext_len > len) return false;
        pos += ext_len;
    }
    return false;
}

bool parse_http_host(const uint8_t* buf, size_t len, char* out_host, size_t host_max_len) {
    const char* data = reinterpret_cast<const char*>(buf);
    size_t search_len = std::min(len, static_cast<size_t>(4096));

    for (size_t i = 0; i + 6 < search_len; ++i) {
        if ((data[i]   == 'H' || data[i]   == 'h') &&
            (data[i+1] == 'O' || data[i+1] == 'o') &&
            (data[i+2] == 'S' || data[i+2] == 's') &&
            (data[i+3] == 'T' || data[i+3] == 't') &&
             data[i+4] == ':') {
            size_t start = i + 5;
            while (start < search_len && data[start] == ' ') ++start;
            size_t end = start;
            while (end < search_len && data[end] != '\r' && data[end] != '\n') ++end;
            // Strip port
            size_t colon = end;
            for (size_t j = start; j < end; ++j) {
                if (data[j] == ':') { colon = j; break; }
            }
            size_t copy_len = std::min(colon - start, host_max_len - 1);
            if (copy_len == 0) return false;
            memcpy(out_host, data + start, copy_len);
            out_host[copy_len] = '\0';
            return true;
        }
    }
    return false;
}

} // namespace netscope
