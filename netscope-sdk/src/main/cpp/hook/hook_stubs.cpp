#include "hook_stubs.h"
#include "../netscope_log.h"
#include "xhook.h"

#include <array>
#include <mutex>

namespace netscope {

// We register at most ~16 stubs (connect, close, getaddrinfo, 8 send/recv
// variants, dlopen, android_dlopen_ext, room for a few future ones). Fixed
// array avoids any allocator interaction on the audit path.
namespace {
constexpr size_t kMaxStubs = 32;
std::array<void*, kMaxStubs> g_stubs{};
size_t                       g_stub_n = 0;
std::mutex                   g_stub_mtx;
} // namespace

int register_stub(const char* regex, const char* sym,
                  void* new_func, void** old_func) {
    int r = xhook_register(regex, sym, new_func, old_func);
    if (r == 0 && new_func) {
        std::lock_guard<std::mutex> lk(g_stub_mtx);
        bool seen = false;
        for (size_t i = 0; i < g_stub_n; ++i) {
            if (g_stubs[i] == new_func) { seen = true; break; }
        }
        if (!seen) {
            if (g_stub_n < g_stubs.size()) {
                g_stubs[g_stub_n++] = new_func;
            } else {
                LOGW("hook_stubs: registry full (%zu); cannot track '%s' stub=%p",
                     g_stubs.size(), sym ? sym : "(null)", new_func);
            }
        }
    } else if (r != 0) {
        LOGE("hook_stubs: xhook_register('%s') failed ret=%d",
             sym ? sym : "(null)", r);
    }
    return r;
}

bool is_registered_stub(void* p) {
    if (!p) return false;
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    for (size_t i = 0; i < g_stub_n; ++i) {
        if (g_stubs[i] == p) return true;
    }
    return false;
}

size_t registered_stub_count() {
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    return g_stub_n;
}

size_t registered_stubs_snapshot(void** out, size_t cap) {
    if (!out || cap == 0) return 0;
    std::lock_guard<std::mutex> lk(g_stub_mtx);
    size_t n = g_stub_n < cap ? g_stub_n : cap;
    for (size_t i = 0; i < n; ++i) out[i] = g_stubs[i];
    return n;
}

} // namespace netscope
