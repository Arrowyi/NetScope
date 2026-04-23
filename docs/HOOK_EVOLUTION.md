# NetScope Hook Backend Evolution & Lessons Learned

This document records every hooking backend NetScope has shipped, what broke,
and what we learned. Read this **before** touching `hook_manager.cpp` or
switching the backend again — you will very likely rediscover one of these
pitfalls otherwise.

## Timeline

| Order | Backend              | Shipped in      | Killed by                                      |
|-------|----------------------|-----------------|------------------------------------------------|
| 1     | shadowhook 1.0.9     | earliest alpha  | inline-hook trampolines need `mmap(PROT_EXEC)` |
| 2     | shadowhook 2.0.0     | `22bc487`       | same W^X problem on HONOR Android 10           |
| 3     | bytehook (bhook)     | `eeaf53f`       | same `mmap(PROT_EXEC)` trampoline crash on W^X ROMs |
| 4     | xhook 1.2.0          | `8934473`       | mis-computes GOT addresses for APK-embedded and some extracted `.so` — stub pointers land in `[anon:libc_malloc]` pages, app crashes minutes later in unrelated virtual calls |
| 5     | bytehook 1.1.1 (retry) | _this commit_ | _TBD — W^X on strict car head-units to be re-tested_ |

## Core problems we keep hitting

### P1. W^X (Write-XOR-Execute) on locked-down Android ROMs

- **Symptom:** `mmap(len, PROT_READ|PROT_EXEC, ...)` returns `EPERM` or the
  kernel kills the process with `SIGSEGV` the moment a newly-allocated
  trampoline is executed.
- **Who triggers it:** shadowhook (inline), bytehook _AUTOMATIC_ mode
  (shared trampoline page for `BYTEHOOK_CALL_PREV`).
- **Devices seen:** HONOR Android 10, some OEM car head-units (IVI).
- **Mitigation:** prefer pure **PLT/GOT patching** (no EXEC allocation
  needed — we only `mprotect(GOT_PAGE, RW)` → store → `mprotect(GOT_PAGE, R)`).
- **With bytehook:** use **`BYTEHOOK_MODE_MANUAL`** and do **not** call
  `BYTEHOOK_CALL_PREV` in proxies. That removes bytehook's trampoline
  allocation from the critical path on init. If the OEM device still fails
  at `bytehook_init`, surface it via `HookStatus.FAILED` with a clear reason
  — **do not try to retry or recover with executable allocations**.

### P2. `orig_*` pointers chain into host app's hook stubs

- **Symptom:** `SIGSEGV` seconds after init, crash PC inside the host
  app's own hook library, not ours.
- **Root cause:** if the app already hooked `connect`/`send`/... before
  NetScope loaded, `xhook`'s `orig_*` value is the app's stub address. If
  the app later uninstalls its hook, our `orig_*` dangles.
- **Fix (kept in the SDK forever after `836b8e0`):** never call
  `orig_*`. Resolve the real libc entry points ourselves via
  `dlsym(RTLD_NEXT, "connect")` at init. See `hook/libc_funcs.{h,cpp}`.
- **Invariant:** proxies in `hook_*.cpp` MUST call `libc().connect(...)`,
  NOT `orig_connect(...)`, NOT `BYTEHOOK_CALL_PREV(...)`.

### P3. xhook 1.2.0 mis-computes GOT for APK-embedded `.so`

- **Symptom:** `extractNativeLibs="false"` builds crash 5–15 min after
  init, always `asdk.httpclient` thread, `pc == x8`, `x8` in
  `[anon:libc_malloc]`. Register fingerprint identical across 6+ crashes
  (`x0 - x1 = 0xce8`, `x17 = 0x7906072620`).
- **Why:** for `/data/app/.../base.apk!/lib/arm64-v8a/libXxx.so`, xhook
  doesn't subtract `PT_LOAD[0].p_offset` when computing `got_va`. The
  "GOT write" lands in some neighbouring heap object, overwriting e.g.
  a C++ virtual-dispatch pointer. App crashes as soon as that object
  is used — minutes later, on an unrelated stack.
- **Attempt 1 (`6f50453`):** `xhook_ignore(".*\\.apk!/.*\\.so$")` to
  skip APK-embedded libs. Worked for `extractNativeLibs=false` but lost
  53 business libraries' coverage. **Did not fix `extractNativeLibs=true`**:
  at least one extracted `.so` still trips xhook's parser.
- **Real fix (this commit):** replace xhook. bytehook does the ELF
  parsing correctly (battle-tested in TikTok/Douyin at scale).

### P4. "Post-install audit" false positives

- **Symptom (`21bb54d`):** init finishes, audit reports
  `slots_corrupt=0` but `heap-stub-hits=22`, triggers `xhook_clear()`
  and `Status.FAILED`. App runs fine but SDK collects nothing.
- **Why:** the "is this a NetScope stub?" check was `is_in_our_text()`
  — any pointer inside libnetscope's `.text` range. That trivially matches:
  - our SIGSEGV handler (legitimately stored in the kernel sigaction table
    adjacent to `app_process64`)
  - libnetscope's load base (stored by `dl_iterate_phdr` / soinfo)
  - xhook's own registry of `new_func` pointers
- **Fix (`ca63cb7`):** `hook/hook_stubs.{h,cpp}` keeps an **exact-match
  set** of pointers actually passed to the hooker as `new_func`.
  `is_registered_stub()` does `O(N)` linear scan over that set (N ≤ 32).
- **Invariant:** never infer "stub" from a range check. Only add a
  pointer to `g_stubs` via `register_stub()`, and never push library
  bases, handlers, or helpers into it.

### P5. `audit_got` self-crash on modern Android anon namespaces

- **Symptom (`6f50453`):** `SIGSEGV SEGV_MAPERR` during init, `pc` inside
  `audit_got()+1676`, `x25` decodes to ASCII `"[anon:sc"` — we were
  scanning a `[anon:scudo_*]` or `[anon:scs:*]` region and stepped off
  the mapped portion.
- **Why:** Android Q+/R+ tag many rw-p anon regions with names like
  `[anon:scudo_primary]`, `[anon:scudo_secondary]`, `[anon:scs:stack]`,
  `[anon:cfi shadow]`, `[anon:dalvik-...]`, `[anon:.bss]`. These are
  reserved VA ranges not all of which are actually backed by physical
  memory, so naive `*(void**)p` reads page-fault.
- **Fix (this commit):** only scan explicitly-named `[anon:libc_malloc]`
  regions (the real C heap). Skip every other anon. Optional: guard
  the scan loop with a `sigsetjmp/siglongjmp` SIGSEGV handler as belt
  and braces.
- **Invariant:** never treat "any rw-p anon with no name or `[anon:...]`
  prefix" as safe to dereference. The set of safe names is:
  `[anon:libc_malloc]` and nothing else.

### P6. Interval-boundary reports are empty unless in-flight flows flush

- **Symptom (pre-flow-flush):** `LogcatReporter` cumulative section shows
  traffic, but `Interval` section is always empty.
- **Why:** `StatsAggregator` only receives bytes when a flow is closed.
  For long-lived connections (HTTP keepalive, WebSocket, HLS video), the
  flow hasn't closed yet when `markIntervalBoundary()` fires.
- **Fix:** `FlowTable::flush_in_flight()` walks live flows at
  boundary and pushes the delta (new tx/rx since last flush) to
  `StatsAggregator`. See `core/flow_table.cpp`.
- **Invariant:** whenever adding a new kind of reporter, think about
  long-lived flows. Ask: does this reporter need `flush_in_flight()`?

### P7. Late-loaded libraries (dlopen) need coverage

- **Symptom:** hooks installed at SDK init miss libraries `dlopen`'d
  later (e.g. `libDriveSessionJni.so` 2s after init).
- **Old approach (xhook):** hook `dlopen` and `android_dlopen_ext`
  ourselves, call `xhook_refresh` in the proxy.
- **New approach (bytehook):** `bytehook_hook_all()` handles this
  automatically via bytehook's own `dl_iterate_phdr`/dlopen integration.
  **Do not** re-implement the dlopen interception in NetScope — it will
  conflict with bytehook's own.
- **Invariant:** if you switch hooker again and the new one doesn't
  handle late-loaded libs, bring the dlopen-hook code back in.

### P8. Trampoline-based hookers are fundamentally incompatible with strict W^X

- You cannot `mmap(PROT_EXEC)` on an IVI kernel that enforces W^X.
- shadowhook (inline) is therefore permanently off the table.
- bytehook is OK in **MANUAL mode only** as long as proxies don't use
  `BYTEHOOK_CALL_PREV`.
- If a future requirement forces us to call the previous hook in a
  chain, we have no viable hooker for W^X devices. Plan around this.

## Golden rules (DO NOT violate without updating this file)

1. **Never call `orig_*` / `BYTEHOOK_CALL_PREV` in a proxy.** Always
   `libc().<fn>()`.
2. **Never mark a pointer as "our stub" via range check.** Use the
   exact-match set in `hook_stubs.{h,cpp}` (one entry per
   `bytehook_hook_all`/`xhook_register` call).
3. **Never scan rw-p anon memory without a name whitelist.** Only
   `[anon:libc_malloc]` is safe.
4. **Never let audit downgrade status on `heap-stub-hits` alone.**
   Only real `slots_corrupt` (dangling GOT → non-executable memory)
   is worth a `FAILED`.
5. **Expose every hook decision through `HookReport`.** The HMI
   integrator cannot debug what we don't report. Add fields generously
   — Kotlin data classes are cheap.
6. **For every integration change, surface a clear `failureReason`.**
   "all hooks failed" is not actionable. "bytehook_init returned 9
   (INITERR_SIG)" is.
7. **When switching hook backends, ALWAYS:**
   - update this file
   - update the Known Limitations in `README.md`
   - bump the hook status reason string so integrators can see the
     change live

## Known-good configurations

| Android | OEM                 | Packaging                 | Hooker            | Status |
|---------|---------------------|---------------------------|-------------------|--------|
| 10      | HONOR AGM3-W09HN    | extractNativeLibs=false   | xhook 1.2.0       | stub writes into heap → crash |
| 10      | HONOR AGM3-W09HN    | extractNativeLibs=true    | xhook 1.2.0       | crash 16–25 s later            |
| 13      | Generic tablet      | either                    | xhook 1.2.0       | stable                         |
| 10      | HONOR AGM3-W09HN    | either                    | bytehook 1.1.1    | _testing now_                  |
| IVI     | OEM car head-unit   | either                    | bytehook 1.1.1    | _W^X risk — to be tested_      |

## If bytehook 1.1.1 fails

Order of fallback plans:

1. **`bytehook_init` fails with INITERR_TRAMPO (code 8) or INITERR_HUB
   (27):** we've hit W^X. Roll back to the `6f50453` xhook path and
   document the device as unsupported.
2. **bytehook installs but we see same `[anon:libc_malloc]` stub-write
   crashes:** unlikely given its test coverage, but the escape hatch is
   to write our own minimal PLT patcher — we already have all the ELF
   parsing in `got_audit.cpp`. Estimated ≤ 300 LOC.
3. **bytehook installs and audit is clean but traffic still doesn't
   flow:** check `HookReport.audit.slots_hooked` vs `slots_total`. If
   `slots_hooked == 0`, bytehook's `hook_all` silently no-op'd; likely
   a `bytehook_add_ignore` of the wrong path.
