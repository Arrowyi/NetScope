#pragma once
//
// Single source of truth for "what are NetScope's hook stub addresses".
//
// Every call into xhook_register() goes through this file. The `new_func`
// pointer passed to xhook is recorded in a small set; the audit layer
// later uses this set (NOT the full libnetscope.so .text range) to
// decide whether a given address was installed by NetScope.
//
// Why: the previous heuristic "is this value inside libnetscope's .text?"
// flagged lots of benign matches as "stub-in-heap":
//   - xhook's own xh_core_hook_info_t registry (which legitimately stores
//     our new_func pointers)
//   - sigaction's handler table entry for our SIGSEGV guard
//   - bionic's soinfo/dl_phdr_info copies of libnetscope.dlpi_addr
// That caused a false-FAILED rollback even though the real GOT was clean.
// Exact-pointer matching closes all three false-positive sources.

#include <cstddef>

namespace netscope {

// Wrap xhook_register: call it, and on success record `new_func` in the
// stub set so is_registered_stub() can see it later. Same return value
// as xhook_register (0 on success).
int register_stub(const char* pathname_regex,
                  const char* symbol,
                  void*       new_func,
                  void**      old_func);

// Fast exact-match query for the audit.
bool is_registered_stub(void* p);

// Diagnostic: how many distinct new_func pointers we've registered so far.
size_t registered_stub_count();

// Diagnostic dump: copy up to `cap` stub pointers into `out` and return
// the actual count written (<= min(cap, registered_stub_count())).
size_t registered_stubs_snapshot(void** out, size_t cap);

} // namespace netscope
