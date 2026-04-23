#pragma once
#include <cstdint>

namespace netscope {

// Overall SDK state, exposed to the upper layer so the host (e.g. an HMI
// surface) can tell the user whether traffic statistics are available.
enum HookStatus : int32_t {
    HOOK_STATUS_NOT_INITIALIZED = 0,   // init() not yet called
    HOOK_STATUS_ACTIVE          = 1,   // all hooks working; full data
    HOOK_STATUS_DEGRADED        = 2,   // some hooks failed; partial data
    HOOK_STATUS_FAILED          = 3,   // critical failure; no data will be collected
};

// Detailed report of which hooks succeeded. Used by the JNI bridge to build
// a Kotlin HookReport data class.
struct HookReport {
    HookStatus status;
    bool libc_resolved;   // all 12 libc symbols resolved via dlsym
    bool connect_ok;
    bool dns_ok;
    bool send_recv_ok;
    bool close_ok;
    // Short human-readable description of why the SDK is DEGRADED / FAILED.
    // Empty when status == ACTIVE.
    char failure_reason[256];
};

int  hook_manager_init();            // returns 0 on ACTIVE / DEGRADED, non-zero on FAILED
void hook_manager_destroy();
void hook_manager_set_paused(bool paused);
bool hook_manager_is_paused();

// True iff hooks are installed AND not paused. Every hook handler should
// gate its stats-collection path on this.
bool hook_manager_is_enabled();

// Snapshot the current status + per-hook flags.
HookReport hook_manager_report();

// Register a C-style callback invoked whenever the overall status changes.
// Called synchronously on whichever thread caused the transition.
using StatusListener = void (*)(const HookReport&, void* user);
void hook_manager_set_status_listener(StatusListener cb, void* user);

} // namespace netscope
