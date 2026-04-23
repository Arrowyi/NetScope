#pragma once
//
// Post-install GOT audit.
//
// After the hooker (currently bytehook 1.1.1) installs all stubs, we walk
// every loaded shared object via dl_iterate_phdr and read the actual GOT
// entry for every relocation whose symbol matches one of NetScope's hooked
// functions (connect / send / recv / …). Each slot's current value is
// classified:
//
//   stub       — exact match against one of NetScope's registered
//                new_func pointers (see hook_stubs.h). Good.
//   libc       — value still equals the real libc symbol we resolved via
//                dlsym. Benign: that lib's GOT was never patched (e.g.
//                bytehook_add_ignore matched it, or it was loaded too late).
//   other-text — points into SOME other library's r-xp region. Another
//                native hooker got there first; not our fault, not a crash
//                risk for us.
//   CORRUPT    — points into rw-p / r--p data or into no mapped region
//                at all. Smoking gun for "the hooker wrote the stub
//                address into the wrong page". This was a real issue
//                under xhook 1.2.0 with extractNativeLibs=false; bytehook
//                handles those layouts correctly, but we keep the audit
//                as a safety net.
//
// Optionally (but by default on) the audit also linearly scans [anon:libc_malloc]
// regions looking for stray copies of our stub addresses. If a stub pointer
// turns up inside the heap, the hooker has written into some third-party
// object — the host app would segfault the moment that object is used.
// See docs/HOOK_EVOLUTION.md §P4 for why this is advisory-only (legitimate
// copies abound in the hooker's own registry / sigaction table / soinfo).
//
// Total cost: GOT walk is ~ms even on big apps; the heap scan is capped
// at 256 MiB, restricted to strictly-named [anon:libc_malloc] / [heap]
// regions, and SIGSEGV-guarded so it can't crash the audit itself.

#include <cstdint>
#include <cstddef>

namespace netscope {

struct GotAuditResult {
    int libs_scanned          = 0;   // total .so files visited
    int libs_skipped          = 0;   // libs without parseable .rela.plt
    int slots_total           = 0;   // relocations matching our hooked symbols
    int slots_to_our_stub     = 0;   // value in libnetscope.so .text range (good)
    int slots_to_real_libc    = 0;   // value == libc().X (lib not patched)
    int slots_to_other_text   = 0;   // value in some OTHER library's r-xp region
    int slots_corrupt         = 0;   // value in rw-p / data / unmapped — CRITICAL

    // Optional heap scan results (zero when scan disabled / found nothing).
    size_t anon_regions_scanned = 0;
    size_t anon_bytes_scanned   = 0;
    int    anon_stub_hits       = 0; // stub addresses found in rw-p anon memory

    // First concrete finding for human-readable logging / HookReport.
    char first_detail[256]     = {};
};

// Run the audit. Safe to call exactly once after hook installation.
// `scan_anon_heap`: if true, also sweep strictly-named heap regions
// ([anon:libc_malloc], [heap]) for stray stub pointers.
GotAuditResult audit_got(bool scan_anon_heap);

} // namespace netscope
