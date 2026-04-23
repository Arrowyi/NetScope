#pragma once
//
// Thin runtime wrapper around libbytehook.so.
//
// We go through dlopen + dlsym for EVERY bytehook entry point instead of
// linking libnetscope.so against libbytehook.so. Reason (HONOR AGM3-W09HN
// / EMUI 11, 2026-04-23):
//
//   When libbytehook.so is in libnetscope.so's DT_NEEDED, Android's
//   dynamic linker loads libbytehook.so (and its own DT_NEEDED
//   libshadowhook.so) as soon as `System.loadLibrary("netscope")` runs.
//   That triggers every __attribute__((constructor)) in the bytehook /
//   shadowhook chain at class-init time — before we ever get a chance
//   to check NetScope.DEBUG_* flags. On EMUI 11 / Magic UI 4.0 one of
//   those constructors (or a resulting DT_NEEDED-side-effect) desta-
//   bilises a code path that asdk.httpclient later hits, producing a
//   tombstone with pc == x8 ∈ [anon:libc_malloc] roughly ~14–24 s after
//   init. Crucially this reproduces even when NetScope itself calls
//   zero bytehook functions (DEBUG_SKIP_HOOKS and DEBUG_ULTRA_MINIMAL
//   both crashed with a bit-identical register fingerprint).
//
// By removing bytehook from DT_NEEDED and only dlopen-ing it inside
// `bh::ensure_loaded()` — which is called the first time the hook
// manager actually needs bytehook — we gain a clean kill switch:
//
//   * DEBUG_ULTRA_MINIMAL: we never call ensure_loaded, so
//     libbytehook.so is never mapped and its constructors never run.
//   * All other modes: bytehook is loaded on demand during
//     hook_manager_init, exactly like before, only a few hundred µs
//     later. No behavioural change on non-affected devices.
//
// If libbytehook.so cannot be dlopen'd (misconfigured host app missing
// the `com.bytedance:bytehook` gradle dep), `ensure_loaded` returns
// BYTEHOOK_STATUS_CODE_NOT_LOADED and all wrapped functions become
// safe no-ops — the hook manager surfaces this as FAILED with a clear
// reason instead of crashing.

#include "bytehook.h"   // types + status codes only; not linked

namespace netscope::bh {

// Our own status code extending bytehook's range. Anything outside
// the 0..29 bytehook range is interpreted as "bytehook is not available
// in this process".
constexpr int BYTEHOOK_STATUS_CODE_NOT_LOADED = 100;

// Lazily dlopen libbytehook.so + dlsym all the entry points NetScope
// uses. Idempotent; subsequent calls cheaply return the cached rc.
int  ensure_loaded();

// True iff ensure_loaded() previously succeeded.
bool available();

// ─── Wrapped bytehook API ───────────────────────────────────────────────
//
// Same signatures as the originals in bytehook.h. Each wrapper calls
// ensure_loaded() first; if the lib is unavailable, the wrapper returns
// a safe sentinel (NOT_LOADED / nullptr / "unloaded") rather than
// crashing. This matches how the native call sites were already writing
// defensive null-checks on register_stub's return value.

int              init           (int mode, bool debug);
bytehook_stub_t  hook_all       (const char* callee_path_name,
                                 const char* sym_name,
                                 void* new_func,
                                 bytehook_hooked_t hooked,
                                 void* hooked_arg);
int              unhook         (bytehook_stub_t stub);
int              add_ignore     (const char* caller_path_name);
void             set_debug      (bool debug);
void             set_recordable (bool recordable);
const char*      get_version    (void);

} // namespace netscope::bh
