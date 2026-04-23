#pragma once
//
// Post-install GOT audit.
//
// After xhook_refresh() completes, we walk every loaded shared object via
// dl_iterate_phdr and read the actual GOT entry for every relocation whose
// symbol matches one of NetScope's hooked functions (connect / send / recv /
// …). Each slot's current value is classified:
//
//   stub       — points into libnetscope.so's executable segment. Good.
//   libc       — value still equals the real libc symbol we resolved via
//                dlsym. Benign: that lib's GOT was never patched (e.g. lib
//                matched xhook_ignore or was loaded too late).
//   other-text — points into SOME other library's r-xp region. Another
//                native hooker got there first; not our fault, not a crash
//                risk for us.
//   CORRUPT    — points into rw-p / r--p data or into no mapped region
//                at all. This is the smoking gun for "xhook wrote the
//                stub address into the wrong page" (a documented issue
//                with xhook 1.2.0 when the APK is built with
//                extractNativeLibs=false — the bionic linker reports
//                path `base.apk!/lib/arm64-v8a/<name>.so` and xhook's
//                ELF parsing can misalign on the segment layout).
//
// Optionally (but by default on) the audit also linearly scans every
// anonymous rw-p region looking for stray copies of our stub addresses.
// If a stub pointer turns up inside [anon:libc_malloc], xhook definitely
// wrote into some third-party heap object — and the host app will segfault
// the moment that object is used (classic "pc == x8, fault in
// [anon:libc_malloc]" pattern).
//
// Total cost: GOT walk is ~ms even on big apps; the heap scan is capped
// at 256 MiB and finishes in hundreds of ms.

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

// Run the audit. Safe to call exactly once after a successful xhook_refresh.
// `scan_anon_heap`: if true, also sweep rw-p anonymous regions for stray
// stub pointers (expensive but conclusive for the xhook-wrote-into-heap
// bug).
GotAuditResult audit_got(bool scan_anon_heap);

} // namespace netscope
