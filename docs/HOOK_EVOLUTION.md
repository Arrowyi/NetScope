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
| 3     | bytehook (bhook) 1.1.1 | `eeaf53f`     | **AUTOMATIC mode + `BYTEHOOK_CALL_PREV`** triggers `bh_hub_init` → `bh_trampo_alloc` → `mmap(PROT_EXEC)`; dies on W^X ROMs. The library is innocent — **the mode choice was wrong**. |
| 4     | xhook 1.2.0          | `8934473`       | mis-computes GOT addresses for APK-embedded and some extracted `.so` — stub pointers land in `[anon:libc_malloc]` pages, app crashes minutes later in unrelated virtual calls |
| 5     | bytehook 1.1.1 (retry) | `68acdfb`     | shipping. Same library as order 3, but now in **`BYTEHOOK_MODE_MANUAL`** with `libc().fn()` calls (no `CALL_PREV`). MANUAL mode's hook path (`bh_switch_hook_unique`, `hub_trampo=NULL`) never reaches `bh_trampo_alloc`, so W^X is structurally unreachable. |

## Core problems we keep hitting

### P1. W^X (Write-XOR-Execute) on locked-down Android ROMs

- **Symptom:** `mmap(len, PROT_READ|PROT_WRITE|PROT_EXEC, ...)` returns
  `EPERM`, or the allocator silently falls back to `malloc` and the
  kernel kills the process with `SIGSEGV` the moment a newly-allocated
  trampoline is executed.
- **Who triggers it:** shadowhook (inline), bytehook _AUTOMATIC_ mode
  (shared trampoline page for `BYTEHOOK_CALL_PREV`). Pinpointed via
  source reading (`bh_trampo.c:82` is the only `mmap(PROT_EXEC)` call
  in all of bytehook; only reachable from `bh_hub_create`; only
  reachable in AUTOMATIC mode or via explicit `BYTEHOOK_CALL_PREV`).
- **Who does NOT trigger it:** bytehook in **`BYTEHOOK_MODE_MANUAL`**
  when proxies call the real libc via `libc().fn()` (resolved by
  `dlsym(RTLD_NEXT)`) instead of `BYTEHOOK_CALL_PREV`. The MANUAL code
  path routes through `bh_switch_hook_unique(..., hub_trampo=NULL)`,
  which never calls `bh_hub_create`, which never calls
  `bh_trampo_alloc`. Verified across bytehook versions 1.0.x – 1.1.1.
- **Devices seen:** HONOR Android 10, some OEM car head-units (IVI).
- **The source of bytehook (Prefab AAR vs vendored C sources) is
  irrelevant to W^X safety.** Both paths ship the identical object
  code; only the init flags and the proxy code decide whether
  `bh_trampo_alloc` is reached.
- **Mitigation:** use **`BYTEHOOK_MODE_MANUAL`** and do **not** call
  `BYTEHOOK_CALL_PREV` in proxies. If `bytehook_init` ever returns
  `INITERR_TRAMPO` / `INITERR_HUB` despite MANUAL mode, that is a
  bytehook version regression — surface the numeric code via
  `HookStatus.FAILED` with a clear reason; **do not retry with
  executable allocations**.

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

### P8. Trampoline-based hooker modes are incompatible with strict W^X

- You cannot `mmap(PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS, ...)`
  on an IVI kernel that enforces W^X / SELinux `execmem` deny.
- Any hooker that _executes on a freshly-allocated anonymous page_ is
  blocked:
  - shadowhook (inline): every hook needs a trampoline; permanently
    off the table for these devices.
  - bytehook **AUTOMATIC**: the shared hub page used by
    `BYTEHOOK_CALL_PREV` is allocated this way. See `bh_trampo.c:82`.
- Hookers that only _modify existing executable pages_ are fine,
  because `mprotect` to temporarily add `PROT_WRITE` to a page that
  was already mapped `PROT_READ|PROT_EXEC` is a different syscall
  with a different policy gate (usually allowed):
  - xhook (GOT patch): fine on W^X, dies from its own ELF-parsing bug
    — that's P3, unrelated.
  - bytehook **MANUAL** + `libc().fn()`: also fine on W^X, because
    it's pure GOT patching too; no anonymous PROT_EXEC page is ever
    allocated.
- If a future requirement forces `BYTEHOOK_CALL_PREV` (hook chaining),
  we have no viable hooker for W^X devices out of the box. Plan
  around this: either resolve the previous hook yourself via
  `dlsym(RTLD_NEXT)`, or vendor bytehook and replace `bh_trampo_alloc`
  with a `memfd_create`-backed dual-mapping implementation (≈ 1 day
  of focused work; see P1 fallback plan).

## Golden rules (DO NOT violate without updating this file)

1. **Never call `orig_*` / `BYTEHOOK_CALL_PREV` in a proxy.** Always
   `libc().<fn>()`. This also keeps bytehook in the MANUAL-mode
   code path (`bh_switch_hook_unique`), which is the reason we don't
   need `mmap(PROT_EXEC)` and therefore don't hit W^X. See P1.
   Corollary: **never flip `bytehook_init` to `BYTEHOOK_MODE_AUTOMATIC`**
   without first replacing `bh_trampo_alloc` with a W^X-safe
   dual-mapping implementation.
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

| Android | OEM                 | Packaging                 | Hooker / mode                  | Status |
|---------|---------------------|---------------------------|--------------------------------|--------|
| 10      | HONOR AGM3-W09HN    | extractNativeLibs=false   | xhook 1.2.0                    | stub writes into heap → crash |
| 10      | HONOR AGM3-W09HN    | extractNativeLibs=true    | xhook 1.2.0                    | crash 16–25 s later |
| 13      | Generic tablet      | either                    | xhook 1.2.0                    | stable |
| 10      | HONOR AGM3-W09HN    | either                    | bytehook 1.1.1 / AUTOMATIC     | crashes — W^X (`eeaf53f`, historical) |
| 10      | HONOR AGM3-W09HN    | either                    | bytehook 1.1.1 / **MANUAL**    | _testing `68acdfb`_ |
| IVI     | OEM car head-unit   | either                    | bytehook 1.1.1 / **MANUAL**    | _W^X structurally unreachable; field-testing `68acdfb`_ |

## Diagnostic mode (`NetScope.setDebugMode`)

When a device survives post-install GOT audit (`slots_corrupt=0`) and reports `ACTIVE`, yet the host app still crashes some time later in a specific thread (e.g. `asdk.httpclient` on HONOR AGM3-W09HN, ~14 s after init), the most likely cause is a **hooker conflict** — the host app's own native stack has its own PLT/GOT hooker whose trampolines live in a heap page, and NetScope's writes redirect calls *past* our proxy into that heap page later in the lifecycle.

Rather than guessing, two bit-flags in `NetScope.setDebugMode()` split the hypothesis space:

| Flag | What it isolates |
|---|---|
| `DEBUG_TRACE_HOOKS` (1) | Every GOT write logs `{caller_lib, symbol, prev, new}`. Lines tagged `CONTESTED` identify libraries that were **already hooked** when bytehook got there — `prev != dlsym(RTLD_NEXT)`. Positive hit ⇒ host-app hooker conflict; mitigate via `bytehook_add_ignore("<lib>.so")` or coordinate load order. Additionally snapshots `/proc/self/maps` + 32 bytes at `libdl.so!__cfi_slowpath`, `libdl.so!dlopen`, `libc.so!abort/raise/malloc/free/connect/send/pthread_create` etc. before and after `bytehook_init`; any VMA or byte-level diff is logged as `init-diff: ...`. |
| `DEBUG_SKIP_HOOKS` (2)  | `bytehook_init` runs (CFI disable, shadowhook trampoline registration, the whole load path) but NetScope registers zero stubs. If the app STILL crashes, the trigger is the bytehook load/init path itself, not NetScope's GOT writes. |
| `DEBUG_ULTRA_MINIMAL` (4) | `bytehook_init` is **not called at all**. NetScope's runtime does nothing beyond `dlsym(RTLD_NEXT)` on ~11 libc symbols. Added 2026-04-23 after HONOR AGM3-W09HN triage proved `DEBUG_SKIP_HOOKS` still crashes with a bit-identical register fingerprint — i.e. the trigger lives inside `bytehook_init` itself, not in our stub writes. |

These flags must be set **before** `NetScope.init()`. See README §"Diagnostic mode" for the HMI recipe.

### 2026-04-23 — HONOR AGM3-W09HN verdict

After `DEBUG_SKIP_HOOKS` and `DEBUG_ULTRA_MINIMAL` both ruled out "NetScope's GOT writes are the trigger", HMI's triage matrix (same APK, toggle only) looked like this:

| # | Config | libnetscope loaded | JNI_OnLoad | nativeInit | bytehook_init | hook_all | Result |
|---|---|---|---|---|---|---|---|
| 0 | netmonitor out of APK | — | — | — | — | — | stable |
| 1 | kill-switch | ✘ | ✘ | ✘ | ✘ | ✘ | stable 180 s |
| 2 | baseline (clean reinstall) | ✔ | ✔ | ✘ | ✘ | ✘ | stable 180 s |
| 3 | `DEBUG_SKIP_HOOKS` | ✔ | ✔ | ✔ | ✔ | ✘ | crash @ +20 s |
| 4 | `DEBUG_TRACE+SKIP` | ✔ | ✔ | ✔ | ✔ | ✘ | crash @ +9 s |
| 5 | `DEBUG_TRACE_HOOKS` | ✔ | ✔ | ✔ | ✔ | ✔ | crash @ +25 s |
| 6 | normal | ✔ | ✔ | ✔ | ✔ | ✔ | crash @ +24 s |

All 6 crashes have bit-identical register fingerprints (`x17` same, `x16/lr` same 12-bit offsets into libart.so, `pc == x8 ∈ [anon:libc_malloc]`) ⇒ deterministic bad dispatch through one specific ART JNI PLT site, not random heap corruption. The row that mattered was #3: `DEBUG_SKIP_HOOKS` still crashes even though bytehook wrote zero stubs, which falsifies every "we wrote a bad pointer" hypothesis and confirms the trigger is inside `bytehook_init` itself (probably shadowhook patching an ART/libc code sequence that the AOSP pattern doesn't match on EMUI 11 / Magic UI 4.0 / MTK Helio P65).

Then HMI's round-2 with `DEBUG_ULTRA_MINIMAL` (`bytehook_init` never called, only `dlsym × 11`) ALSO crashed with the same fingerprint. init-diff confirmed the only byte-level change on the system was `libdl.so!__cfi_slowpath` — that's expected shadowhook behaviour on a normal EMUI 11 boot, NOT the trigger. **Conclusion:** the trigger fires between "`libnetscope.so` has been mapped" and "`nativeInit` returns" — i.e. somewhere in a static constructor. Suspects: `libnetscope.so` itself (no constructors we own), `libbytehook.so` (pulled in via `DT_NEEDED`), `libshadowhook.so` (bytehook's own `DT_NEEDED`).

### 2026-04-23 — Mitigation: strip libbytehook.so from DT_NEEDED

Committed in the same day as the round-2 triage. Changes:

* `netscope-sdk/src/main/cpp/CMakeLists.txt`: `find_package(bytehook)` is used for **headers only**; `target_link_libraries` no longer lists `bytehook::bytehook`. Net result: `readelf -d libnetscope.so` no longer shows `[libbytehook.so]` as `DT_NEEDED`. Transitively, `libshadowhook.so` also disappears.
* New file `hook/bytehook_runtime.{h,cpp}` provides `netscope::bh::{init,hook_all,unhook,add_ignore,set_debug,set_recordable,get_version}` — a thin dlopen+dlsym wrapper over the seven bytehook entry points NetScope uses. The first wrapper call `dlopen("libbytehook.so", RTLD_NOW | RTLD_GLOBAL)` and resolves the seven symbols once; subsequent calls are inlined-pointer dispatch.
* `NetScopeNative.kt` no longer calls `System.loadLibrary("bytehook")` in its static initialiser. Instead `NetScope.init()` does a late, guarded `tryLoadBytehook()` — **except** when `DEBUG_ULTRA_MINIMAL` is set, in which case bytehook is never loaded at all and `libbytehook.so` / `libshadowhook.so` never appear in `/proc/self/maps`.

Kill-switch semantics after this commit:

| Flag | libbytehook.so mapped? | libshadowhook.so mapped? | `bytehook_init`? |
|---|---|---|---|
| default | ✔ (dlopen at init) | ✔ (transitive) | ✔ |
| `DEBUG_SKIP_HOOKS` | ✔ | ✔ | ✔ (but no stubs) |
| `DEBUG_ULTRA_MINIMAL` | ✘ | ✘ | ✘ |

This is the cleanest kill-switch we can offer without vendoring bytehook. If `DEBUG_ULTRA_MINIMAL` on this commit still crashes, the trigger must live either inside libnetscope.so's own code (no constructors we own; only libc++_shared, libm, libandroid, liblog, libdl, libc in DT_NEEDED) or inside a host-app side effect that tracks any new `.so` in the loader list.

Verification (run locally + in field):
* `llvm-readelf -d libnetscope.so | grep NEEDED` → no `libbytehook.so`
* On-device with `DEBUG_ULTRA_MINIMAL` + `adb shell 'grep -E "libbytehook|libshadowhook" /proc/$(pidof <app>)/maps'` → empty
* On-device without the flag → both libs present after `nativeInit`

## If bytehook 1.1.1 fails

Order of fallback plans:

1. **`bytehook_init` returns `INITERR_TRAMPO` (8) or `INITERR_HUB`
   (27):** should never happen under MANUAL mode (those codes sit
   behind `bh_hub_init`, which AUTOMATIC-only). If you see them:
   either someone flipped the mode back to AUTOMATIC, or the bytehook
   source drifted. Inspect the `g_report.failure_reason` string — it
   carries the numeric code.
2. **`bytehook_init` returns `INITERR_CFI` (10):** the OEM refuses to
   `mprotect(RWX)` on libdl's `__cfi_slowpath`. Traffic collection
   still works but CFI-protected callers won't go through our proxy.
   Surface as `DEGRADED`, do not roll back.
3. **bytehook installs but we see same `[anon:libc_malloc]` stub-write
   crashes:** unlikely given its test coverage, but the escape hatch is
   to write our own minimal PLT patcher — we already have all the ELF
   parsing in `got_audit.cpp`. Estimated ≤ 300 LOC.
4. **bytehook installs and audit is clean but traffic still doesn't
   flow:** check `HookReport.audit.slots_hooked` vs `slots_total`. If
   `slots_hooked == 0`, bytehook's `hook_all` silently no-op'd; likely
   a `bytehook_add_ignore` of the wrong path.
5. **Need `BYTEHOOK_CALL_PREV` semantics in the future:** vendor
   bytehook and replace `bh_trampo_alloc` with a dual-mapping version
   (`memfd_create` → `mmap(RW)` alias + `mmap(RX)` alias backed by the
   same fd). Do **not** try to flip AUTOMATIC mode on without this
   change — it will W^X-crash on the car head-units. See P8.
