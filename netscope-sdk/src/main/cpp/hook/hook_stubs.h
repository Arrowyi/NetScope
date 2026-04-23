#pragma once
//
// Single source of truth for "what are NetScope's hook stub addresses".
//
// Every hook registration goes through this file. The `new_func` pointer
// passed to bytehook is recorded in a small set; the audit layer later
// uses this set (NOT a range check over libnetscope.so's .text) to decide
// whether a given address was installed by NetScope.
//
// Why exact-match instead of range check (docs/HOOK_EVOLUTION.md §P4):
// the range-check heuristic flagged lots of benign matches as
// "stub-in-heap":
//   - the hooker's own internal registry (which legitimately stores our
//     new_func pointers)
//   - sigaction's handler table entry for our SIGSEGV guard
//   - bionic's soinfo/dl_phdr_info copies of libnetscope.dlpi_addr
// That caused a false-FAILED rollback even though the real GOT was clean.
// Exact-pointer matching closes all three false-positive sources.

#include <cstddef>

namespace netscope {

// Register a hook. Internally calls bytehook_hook_all("libc.so", symbol,
// new_func, ...) and, on success, records `new_func` in the exact-match
// set so is_registered_stub() can see it later.
//
// Signature retained from the xhook era for source compatibility:
//   - `pathname_regex` is ignored (bytehook_hook_all patches every caller)
//   - `old_func`       is ignored (we do NOT use hooker's prev pointer;
//                        every proxy calls libc().<fn>() via dlsym)
//
// Returns 0 on success, non-zero on failure.
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

// Uninstall every stub we previously registered via register_stub().
// Calls bytehook_unhook() for each handle and clears the exact-match set.
// Used by hook_manager during emergency rollback (e.g. if the post-install
// audit detects real corruption).
void unhook_all_stubs();

} // namespace netscope
