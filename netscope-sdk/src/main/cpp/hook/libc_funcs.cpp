#include "libc_funcs.h"
#include "../netscope_log.h"
#include <dlfcn.h>
#include <atomic>

namespace netscope {

static LibcFuncs g_libc;
static std::atomic<bool> g_resolved{false};

// Resolve a single symbol via dlsym(RTLD_NEXT). Log and return success bit.
template <typename Fn>
static bool pick(Fn& out, const char* name) {
    void* sym = dlsym(RTLD_NEXT, name);
    if (!sym) {
        // RTLD_NEXT can fail if libnetscope is dlopen()ed with RTLD_LOCAL and
        // the resolver can't see past it. Fall back to libc.so explicitly.
        void* libc_handle = dlopen("libc.so", RTLD_NOW | RTLD_NOLOAD);
        if (!libc_handle) libc_handle = dlopen("libc.so", RTLD_NOW);
        if (libc_handle) sym = dlsym(libc_handle, name);
    }
    out = reinterpret_cast<Fn>(sym);
    if (!out) LOGE("libc_funcs: dlsym('%s') failed: %s", name, dlerror());
    return out != nullptr;
}

int resolve_libc_funcs() {
    if (g_resolved.load()) {
        // Already done; return cached count (recompute cheap)
        int n = 0;
        if (g_libc.connect)      ++n;
        if (g_libc.close)        ++n;
        if (g_libc.getaddrinfo)  ++n;
        if (g_libc.send)         ++n;
        if (g_libc.sendto)       ++n;
        if (g_libc.write)        ++n;
        if (g_libc.writev)       ++n;
        if (g_libc.recv)         ++n;
        if (g_libc.recvfrom)     ++n;
        if (g_libc.read)         ++n;
        if (g_libc.readv)        ++n;
        return n;
    }

    int ok = 0;
    ok += pick(g_libc.connect,     "connect");
    ok += pick(g_libc.close,       "close");
    ok += pick(g_libc.getaddrinfo, "getaddrinfo");
    ok += pick(g_libc.send,        "send");
    ok += pick(g_libc.sendto,      "sendto");
    ok += pick(g_libc.write,       "write");
    ok += pick(g_libc.writev,      "writev");
    ok += pick(g_libc.recv,        "recv");
    ok += pick(g_libc.recvfrom,    "recvfrom");
    ok += pick(g_libc.read,        "read");
    ok += pick(g_libc.readv,       "readv");

    g_resolved.store(true);
    LOGI("libc_funcs: resolved %d/11 symbols", ok);
    return ok;
}

const LibcFuncs& libc() { return g_libc; }

} // namespace netscope
