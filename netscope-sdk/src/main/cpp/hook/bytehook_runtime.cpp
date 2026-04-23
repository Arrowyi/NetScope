#include "bytehook_runtime.h"
#include "../netscope_log.h"

#include <dlfcn.h>
#include <atomic>
#include <mutex>

namespace netscope::bh {

namespace {

// Function-pointer table. Populated exactly once by do_load(); zero
// until then. Every wrapper null-checks before dispatching.
struct Api {
    decltype(&::bytehook_init)           init           = nullptr;
    decltype(&::bytehook_hook_all)       hook_all       = nullptr;
    decltype(&::bytehook_unhook)         unhook         = nullptr;
    decltype(&::bytehook_add_ignore)     add_ignore     = nullptr;
    decltype(&::bytehook_set_debug)      set_debug      = nullptr;
    decltype(&::bytehook_set_recordable) set_recordable = nullptr;
    decltype(&::bytehook_get_version)    get_version    = nullptr;
};

Api                g_api;
std::once_flag     g_once;
std::atomic<int>   g_load_rc{BYTEHOOK_STATUS_CODE_NOT_LOADED};
std::atomic<bool>  g_ok{false};

template <typename Fn>
bool dlsym_into(void* handle, Fn& out, const char* name) {
    void* s = dlsym(handle, name);
    out = reinterpret_cast<Fn>(s);
    if (!s) {
        const char* err = dlerror();
        LOGE("bh_runtime: dlsym('%s') failed: %s",
             name, err ? err : "(null)");
    }
    return s != nullptr;
}

void do_load() {
    // RTLD_NOW + RTLD_GLOBAL:
    //   NOW    — surface any missing bytehook symbol up-front, not on
    //            first call. Keeps all failure modes in one place.
    //   GLOBAL — bytehook's internal glue resolves by-name against the
    //            global symbol scope (shadowhook looks up its own
    //            entry points that way). Private scope would work in
    //            most cases but is a known footgun on some OEM loaders;
    //            the cost of GLOBAL is a few extra symbols in the
    //            global table and we're already paying it under
    //            DT_NEEDED today.
    void* handle = dlopen("libbytehook.so", RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        const char* err = dlerror();
        LOGE("bh_runtime: dlopen(libbytehook.so) FAILED: %s. Is the host "
             "app missing `com.bytedance:bytehook:1.1.1` as a transitive "
             "dep? See README Integration §.",
             err ? err : "(null)");
        g_load_rc.store(BYTEHOOK_STATUS_CODE_NOT_LOADED);
        g_ok.store(false);
        return;
    }

    int resolved = 0;
    resolved += (int)dlsym_into(handle, g_api.init,           "bytehook_init");
    resolved += (int)dlsym_into(handle, g_api.hook_all,       "bytehook_hook_all");
    resolved += (int)dlsym_into(handle, g_api.unhook,         "bytehook_unhook");
    resolved += (int)dlsym_into(handle, g_api.add_ignore,     "bytehook_add_ignore");
    resolved += (int)dlsym_into(handle, g_api.set_debug,      "bytehook_set_debug");
    resolved += (int)dlsym_into(handle, g_api.set_recordable, "bytehook_set_recordable");
    resolved += (int)dlsym_into(handle, g_api.get_version,    "bytehook_get_version");

    if (resolved != 7) {
        LOGE("bh_runtime: only %d/7 bytehook symbols resolved — disabling",
             resolved);
        g_api = Api{};
        g_load_rc.store(BYTEHOOK_STATUS_CODE_NOT_LOADED);
        g_ok.store(false);
        return;
    }

    const char* ver = g_api.get_version();
    LOGI("bh_runtime: libbytehook.so loaded via dlopen, 7/7 symbols OK, ver=%s",
         ver ? ver : "?");
    g_load_rc.store(BYTEHOOK_STATUS_CODE_OK);
    g_ok.store(true);
}

} // namespace

int  ensure_loaded() { std::call_once(g_once, do_load); return g_load_rc.load(); }
bool available()     { return g_ok.load(); }

// ── Wrapped API ────────────────────────────────────────────────────────

int init(int mode, bool debug) {
    ensure_loaded();
    return g_api.init ? g_api.init(mode, debug)
                      : BYTEHOOK_STATUS_CODE_NOT_LOADED;
}

bytehook_stub_t hook_all(const char* callee, const char* sym, void* new_func,
                         bytehook_hooked_t hooked, void* hooked_arg) {
    return g_api.hook_all
        ? g_api.hook_all(callee, sym, new_func, hooked, hooked_arg)
        : nullptr;
}

int unhook(bytehook_stub_t stub) {
    return g_api.unhook ? g_api.unhook(stub)
                        : BYTEHOOK_STATUS_CODE_NOT_LOADED;
}

int add_ignore(const char* caller) {
    return g_api.add_ignore ? g_api.add_ignore(caller)
                            : BYTEHOOK_STATUS_CODE_NOT_LOADED;
}

void set_debug(bool debug) {
    if (g_api.set_debug) g_api.set_debug(debug);
}

void set_recordable(bool recordable) {
    if (g_api.set_recordable) g_api.set_recordable(recordable);
}

const char* get_version(void) {
    return g_api.get_version ? g_api.get_version() : "unloaded";
}

} // namespace netscope::bh
