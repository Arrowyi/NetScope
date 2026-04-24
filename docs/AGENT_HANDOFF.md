# NetScope — Agent Handoff

> Read this first if you are picking up NetScope maintenance, whether as a
> human engineer or as an AI coding assistant. It is a distilled, action-
> oriented companion to [`HOOK_EVOLUTION.md`](HOOK_EVOLUTION.md), focused on
> how to make the right decisions fast — not on re-telling the history.
>
> Current head: `d98e49c` (2026-04-23). Every statement below is accurate as
> of that commit; the status of the file itself is a good first check.

---

## 1. What NetScope is, in three sentences

NetScope is an Android SDK that collects **per-domain** network traffic
statistics for the embedding app, covering both Java (OkHttp / HttpsURLConnection)
and NDK / C++ traffic, **without** VPN or root. It hooks a handful of libc
networking syscalls (`connect`, `close`, `getaddrinfo`, `send*` / `recv*` /
`write*` / `read*`) in every loaded `.so` via **GOT / PLT patching** so every
socket becomes observable. Domain attribution is layered: TLS SNI, HTTP Host
header, DNS cache reverse lookup — whichever hits first wins.

**Primary deployment surface:** IVI / car head-units (Android Automotive,
HONOR / Huawei / Geely / etc.) where `VpnService` is unavailable and kernels
frequently enforce W^X.

---

## 2. Architecture map (where to look for what)

```
netscope-sdk/src/main/
├── kotlin/indi/arrowyi/netscope/sdk/
│   ├── NetScope.kt              ← public entry point; init/pause/destroy; DEBUG_* flags
│   ├── NetScopeNative.kt        ← JNI bridge; System.loadLibrary("netscope")
│   ├── HookReport.kt            ← data class mirroring C++ HookReport
│   ├── DomainStats.kt           ← per-domain counter record
│   └── LogcatReporter.kt        ← optional periodic `adb logcat` dump
└── cpp/
    ├── netscope_jni.cpp         ← JNI_OnLoad + RegisterNatives
    ├── hook/
    │   ├── hook_manager.{h,cpp} ← orchestrates init; owns HookReport; SIGSEGV guard
    │   ├── hook_stubs.{h,cpp}   ← central register_stub() + exact-match set
    │   ├── hook_connect.cpp     ← connect() proxy
    │   ├── hook_close.cpp       ← close() proxy
    │   ├── hook_dns.cpp         ← getaddrinfo() proxy
    │   ├── hook_send_recv.cpp   ← all 8 send/recv/read/write variants
    │   ├── libc_funcs.{h,cpp}   ← dlsym(RTLD_NEXT) cache of real libc
    │   ├── got_audit.{h,cpp}    ← post-install GOT verifier; rollback logic
    │   └── bytehook_runtime.{h,cpp} ← dlopen+dlsym wrapper over libbytehook.so  (b500638)
    ├── core/
    │   ├── flow_table.cpp       ← per-fd byte counters; flush_in_flight for boundary
    │   ├── stats_aggregator.cpp ← per-domain atomic counters
    │   └── dns_cache.cpp        ← IP → domain, 60s TTL
    └── utils/
        ├── tls_sni_parser.cpp
        └── ip_utils.cpp
```

**Mental model:** one proxy per libc symbol → all accounting into `FlowTable`
(keyed by fd) → flushed into `StatsAggregator` (keyed by domain) at
connection close **and** at interval boundary.

---

## 3. Golden rules (DO NOT violate without updating `HOOK_EVOLUTION.md`)

These are the invariants the codebase has been bled into. Each one has a
dedicated bug story; see the paragraph reference.

| # | Rule | Rationale | See |
|---|---|---|---|
| G1 | **Never call `orig_*` / `BYTEHOOK_CALL_PREV` in a proxy.** Always `libc().fn()`. | Host-app hooks that exit between our init and our call leave `orig_*` dangling → SEGV in third-party code. Also keeps bytehook in W^X-safe MANUAL mode. | P1, P2 |
| G2 | **Never mark a pointer as "our stub" by range check.** Only exact-match via `hook_stubs.cpp`. | Range checks false-positive on our SIGSEGV handler, lib load base, hooker registry → audit wrongly rolls back. | P4 |
| G3 | **Never dereference rw-p anon memory without a name whitelist.** Only `[anon:libc_malloc]` is safe. | Android Q+ tags many anons (`[anon:scudo_*]`, `[anon:scs:*]`, `[anon:cfi shadow]`) that are VA-reserved but not page-backed. | P5 |
| G4 | **`heap-stub-hits > 0` is advisory only.** Force `FAILED` only on `slots_corrupt > 0`. | Bytehook's own task registry and bionic's sigaction table legitimately store our stub pointers. | P4 |
| G5 | **Every decision path must surface a human-readable `failureReason`.** | Integrators cannot debug what we don't report. "all hooks failed" is not actionable; "bytehook_init returned 9 (INITERR_SIG)" is. | — |
| G6 | **Never flip `bytehook_init` to `BYTEHOOK_MODE_AUTOMATIC`** without first replacing `bh_trampo_alloc` with a W^X-safe dual-mapping implementation. | AUTOMATIC → `bh_hub_create` → `mmap(PROT_EXEC)` → crash on every IVI. | P1, P8 |
| G7 | **Never put `libbytehook.so` back into `DT_NEEDED`.** Use `bytehook_runtime.h` (dlopen + dlsym). | Load-time constructors of bytehook / shadowhook crash some OEM hosts (HONOR AGM3-W09HN). The dlopen path is the only clean kill-switch. | 2026-04-23 entry |
| G8 | **`NetScopeNative.init {}` MUST only `System.loadLibrary("netscope")`.** The bytehook load is a guarded, late call from `NetScope.init()`. | Pre-loading bytehook in the static initialiser defeats G7 and `DEBUG_ULTRA_MINIMAL`. | 2026-04-23 entry |
| G9 | **Every `register_stub()` must be reflected in `got_audit`.** If you add a symbol, add it to the audit's symbol whitelist. | Otherwise the audit walks one less relocation, and a corrupt write into that slot goes undetected. | `got_audit.cpp` `kSymbols[]` |
| G10 | **Any new long-lived reporter must call `FlowTable::flush_in_flight()` before reading.** | Interval stats were empty for HTTP keepalive / HLS streams until we fixed this. | P6 |
| G11 | **Hook install is wrapped in `sigsetjmp` + per-thread guard.** Do not remove it. | Some vendor libraries have malformed GOT layouts that bytehook trips on; we need to survive that. | `hook_manager.cpp::install_sigsegv_guard` |

---

## 4. Playbooks

### 4.1 You got a field crash report. What now?

**Triage order — follow it top to bottom, stop at the first definitive signal.**

1. **Get `HookReport` at +5s / +15s / +30s.** If `status == FAILED`, the
   `failureReason` tells you which layer died. Jump straight there.
2. **Is the crash in NetScope code?** Tombstone `pc` ∈ `libnetscope.so`
   range → likely a proxy bug or an `orig_*` call slipped back in (G1).
   Very rare.
3. **Is `pc == x8` and `x8 ∈ [anon:libc_malloc]`?** This is the
   signature pattern for hooker-conflict / bad-dispatch crashes. Ask the
   integrator to run with `setDebugMode(NetScope.DEBUG_TRACE_HOOKS)` and
   look for:
   * `CONTESTED` lines → another PLT hooker got there first. Mitigate
     via `bytehook_add_ignore("<their.so>")` or advise the integrator
     to coordinate load order.
   * `init-diff: ... CHANGED` outside `libdl.so!__cfi_slowpath` →
     shadowhook pattern-matched the wrong bytes on this ROM. That's
     a bytehook regression — file upstream and plan a fallback.
4. **Same fingerprint (identical `x17` low 12 bits) across runs?**
   Deterministic hook site — NOT memory corruption. Walk the
   `DEBUG_SKIP_HOOKS` → `DEBUG_ULTRA_MINIMAL` ladder (README §"Recommended
   recipe"). Each step removes one thing NetScope does.
5. **If `DEBUG_ULTRA_MINIMAL` still reproduces** → The SDK contact
   surface is at its theoretical minimum (see §5 below). The trigger is
   outside the SDK. Update the `README.md` "Known incompatible hosts"
   table and recommend one of the three integrator workarounds (model
   allow-list / deferred init / ship DEGRADED).
6. **Only then consider** vendoring bytehook or writing our own PLT
   patcher. Cost: ~1 week; gain: rarely solves the actual problem.

**Never** do any of these as a first response:
- Add a try/catch / SIGSEGV swallow in the hot path. (We have one in
  hook install — that's the only acceptable place.)
- Downgrade `Status.FAILED` to `DEGRADED` "to keep the app alive".
  Integrators need the truth.
- Make hooks optional via allow-lists without understanding why they
  crashed. If bytehook breaks on lib X, `bytehook_add_ignore` it, but
  leave a paper trail in the commit message and the known-limitations
  table.

### 4.2 You need to add a new libc hook

Checklist:

1. Add the proxy in `hook_<category>.cpp`. Proxy MUST call
   `libc().fn(...)` (not `orig_*`, not `BYTEHOOK_CALL_PREV`). See G1.
2. Add the symbol to `libc_funcs.{h,cpp}`. Resolve via
   `dlsym(RTLD_NEXT, ...)` in `resolve_libc_funcs()`. Bump the "11
   symbols" count in `NetScope.kt` KDoc if this is a net addition.
3. Call `register_stub(".*", "fn", &proxy, nullptr)` from
   `install_hook_<category>()`. Check the return value.
4. Add `"fn"` to `got_audit.cpp`'s `kSymbols[]`. See G9.
5. Verify with a local Robolectric test + an on-device smoke test;
   confirm the audit reports the new slot as `hooked`, not `unhooked`.

### 4.3 You are considering swapping the hook backend

Before writing any code, re-read §"Timeline" and §"Known-good
configurations" in `HOOK_EVOLUTION.md`. We have already burned through
five backends. Every new backend must answer:

| Question | Minimum bar |
|---|---|
| Does it handle `extractNativeLibs="false"` (ELF inside `base.apk`)? | P3 shows xhook failed this. Test with a production-packed APK. |
| Does it work on strict W^X (no `mmap(PROT_EXEC)` allowed)? | Any inline-hooker fails here. Only pure GOT patch is safe. See G6. |
| Does it auto-apply to late-`dlopen`'d libraries? | Bytehook yes, older xhook no. If no, you'll need to re-introduce the dlopen hook (deleted in `78c3b91`). |
| Does it let us **avoid** a `call-prev` trampoline? | Mandatory. We resolve real libc ourselves via `dlsym(RTLD_NEXT)`. G1. |
| Can we dlopen it lazily (i.e., not a `DT_NEEDED`)? | Mandatory since 2026-04-23. G7. |

If it passes all five, still do an HMI field test on AGM3-W09HN before
removing bytehook.

### 4.4 You are debugging JitPack build failures

Known AGP 7.4.x prefab bug: any stderr output from the `prefab-cli`
subprocess (e.g. Oracle JDK 17 echoing `JAVA_TOOL_OPTIONS`) is
interpreted as a fatal error. Fix: `env -u JAVA_TOOL_OPTIONS` the
gradle invocation. Already in `jitpack.yml`; also required locally.
See commit `2d6ff99`.

---

## 5. Contact surface after `DEBUG_ULTRA_MINIMAL` (post-`b500638`)

This is the theoretical minimum the SDK can leave on the host process
while still being "loaded":

1. `libnetscope.so` is mapped. `DT_NEEDED`: only `liblog`, `libandroid`,
   `libdl`, `libm`, `libc++_shared`, `libc` — zero third-party deps.
2. `JNI_OnLoad` registers native methods for the `NetScopeNative` class.
   No other ART interaction.
3. `dlsym(RTLD_NEXT, ...)` × 11 on libc networking symbols. Read-only
   linker work; no writes anywhere.
4. `setStatusListener(cb)` stores a `std::function` slot in NetScope's
   own static.
5. One `@Synchronized` Kotlin block on the `NetScope` object.

Everything else (bytehook init, CFI disable, shadowhook trampoline
registration, GOT writes, GOT audit, heap scan) is gated behind the
default flag and **does not run** under `DEBUG_ULTRA_MINIMAL`.

If a crash reproduces on this surface on a specific host, there is no
further lever inside the SDK — the trigger is outside. See
`HOOK_EVOLUTION.md` "2026-04-23 — Final verdict on b500638" for the
HONOR AGM3-W09HN case study.

A `DEBUG_INERT` flag that would skip even the 11 `dlsym` calls is
**not** implemented but is a legitimate next step if another incompatible
device surfaces and we need one more data point. ~20 LOC in
`hook_manager.cpp::hook_manager_init()`.

---

## 6. Known incompatibilities (live list)

Always check `README.md` → "Known incompatible hosts" first — that is the
normative list. The table below is a summary and pointers for triage.

| Device | Host stack | Status | Action |
|---|---|---|---|
| HONOR AGM3-W09HN / EMUI 11 / MTK Helio P65 | Telenav `asdk.httpclient` | **Crashes even with `DEBUG_ULTRA_MINIMAL` on `b500638`.** Trigger outside SDK. | Gate NetScope init by `Build.MODEL` allow-list in host; or ship DEGRADED; or investigate host-side (asdk internal hooker / EMUI linker / C++ vtable). |
| All IVI with W^X | any | **Safe** on bytehook 1.1.1 MANUAL. | Default config. |
| `extractNativeLibs="false"` APKs | any | **Safe** on bytehook. (Was broken on xhook.) | Default config. |

If you add a new incompatible entry:

1. Reproduce it three times with identical fingerprint (same `x17` /
   same abort msg / same thread name).
2. Capture `getprop` + `/proc/<pid>/maps` sample + tombstone.
3. Update `README.md` "Known incompatible hosts".
4. Add a dated subsection in `HOOK_EVOLUTION.md` with the matrix of
   diagnostic flags tried and what each did.

---

## 7. Diagnostic flags — quick reference

Set via `NetScope.setDebugMode(flags)` **before** `NetScope.init()`.
Bitwise OR is supported.

| Flag | Effect | Production-safe? |
|---|---|---|
| `DEBUG_NONE` (0) | Default. | ✔ |
| `DEBUG_TRACE_HOOKS` (1) | Per-write log, `CONTESTED` detection, `init-diff` byte-level probe of libc/libdl around `bytehook_init`. | ✔ (verbose) |
| `DEBUG_SKIP_HOOKS` (2) | `bytehook_init` runs, 0 stubs installed. Traffic NOT collected. | ✘ diagnostic |
| `DEBUG_ULTRA_MINIMAL` (4) | `bytehook_init` NOT called; `libbytehook.so` / `libshadowhook.so` never mapped. Traffic NOT collected. | ✘ diagnostic |

Rules:
- Additive. `DEBUG_TRACE_HOOKS | DEBUG_ULTRA_MINIMAL` is valid.
- Higher-tier flags (SKIP, ULTRA_MINIMAL) short-circuit at their own
  layer; trace still logs whatever does run.
- A new tier gets its own constant; don't overload existing ones.
- `NetScope.init()` reads `cachedDebugFlags` on the Kotlin side to
  decide whether to call `System.loadLibrary("bytehook")`. Do not
  remove that check — it's the only thing that keeps `DEBUG_ULTRA_MINIMAL`
  from still mapping `libbytehook.so`.

---

## 8. Build and release

```bash
# Local build — clears the AGP 7.4 prefab stderr bug
env -u JAVA_TOOL_OPTIONS ./gradlew :netscope-sdk:assembleRelease

# Verify DT_NEEDED stays clean (G7)
$NDK/toolchains/llvm/prebuilt/*/bin/llvm-readelf -d \
  netscope-sdk/build/intermediates/stripped_native_libs/release/out/lib/arm64-v8a/libnetscope.so \
  | grep NEEDED
# Expected: liblog, libandroid, libdl, libm, libc++_shared, libc — nothing else.

# Sanity-check we still call bytehook (just via dlsym)
strings netscope-sdk/build/intermediates/cmake/release/obj/arm64-v8a/libnetscope.so \
  | grep -E '^libbytehook\.so$|^bytehook_'
# Expected: "libbytehook.so" (the dlopen arg) + 7 dlsym target names.
```

**Publishing**: JitPack watches `main`. Push a commit, JitPack kicks off
an arm64-v8a + armeabi-v7a release build. Monitor via the JitPack web
UI; the build log is essential when debugging failures. `jitpack.yml`
handles the `JAVA_TOOL_OPTIONS` workaround.

---

## 9. Commit-log landmarks (recent-first)

Read in reverse order if you're new; each one is a story.

| Commit | One-liner | Why it matters |
|---|---|---|
| `d98e49c` | doc: b500638 final verdict; known-incompatible hosts | Closes AGM3-W09HN investigation from SDK side. |
| `b500638` | soft-load libbytehook.so via dlopen; remove from DT_NEEDED | G7, G8. Only kill-switch for load-time bytehook constructor side effects. |
| `4ec8fb9` | DEBUG_ULTRA_MINIMAL + init-diff logger | Proved `bytehook_init` isn't the AGM3 trigger. |
| `5eed945` | DEBUG_TRACE_HOOKS / DEBUG_SKIP_HOOKS | First diagnostic ladder; revealed where AGM3 crash lives. |
| `2d6ff99` | jitpack: unset JAVA_TOOL_OPTIONS | AGP 7.4 prefab stderr bug workaround. |
| `c7f801d` | remove xhook remnants | Final cut-over to pure bytehook. |
| `68acdfb` | replace xhook with bytehook MANUAL | Backend switch 5; current default. |
| `ca63cb7` | heap-stub-hits no longer force FAILED | G4. |
| `21bb54d` | add post-install GOT audit | Origin of `got_audit.cpp`. |
| `836b8e0` | `dlsym(RTLD_NEXT)` real libc | G1. Birth of `libc_funcs.{h,cpp}`. |
| `8934473` | replace bhook with xhook | Backend switch 3. Hooker-history swings: W^X fix, then xhook ELF bug. |
| `eeaf53f` | replace shadowhook with bhook | Backend switch 2. First attempt at W^X-safe. |

---

## 10. Things I wish someone had told me on day 1

- **Bytehook's `BYTEHOOK_MODE_MANUAL` vs `AUTOMATIC` is the whole
  W^X story.** The library is not the problem; the mode is. See P1.
- **`pc == x8`, fault addr in `[anon:libc_malloc]`** is a specific
  fingerprint pattern for "the dispatch target lives in a heap
  trampoline that is no longer valid / was never valid." When you see
  it, immediately suspect another PLT hooker, not ours.
- **Identical `x17` across multiple PIDs** in the same boot means you
  are looking at a deterministic call site, not corruption. The zygote
  relocates libart.so to a per-boot base; the low 12 bits of `x17` are
  a signature of the specific hooked PLT slot within libart.so.
- **Don't confuse "audit is clean" with "the SDK is safe".** A clean
  audit proves we wrote the right pointers into the right slots. It
  says nothing about whether another component is now unhappy that we
  wrote at all.
- **"DT_NEEDED is cheap" is a lie.** Every third-party library in
  DT_NEEDED gets its static constructors run at `System.loadLibrary`
  time, before you can reason about anything. If you can soft-load, do.
- **Document every abandoned path.** Future-you will re-propose it
  otherwise. `HOOK_EVOLUTION.md` exists for this reason.

---

## Files you should read before touching anything

1. This file — `docs/AGENT_HANDOFF.md`.
2. `docs/HOOK_EVOLUTION.md` — full history, all problems P1–P8.
3. `README.md` — integrator-facing; "Diagnostic mode" + "Known
   incompatible hosts" are your contract with integrators.
4. `netscope-sdk/src/main/cpp/hook/hook_manager.cpp` — control flow.
5. `netscope-sdk/src/main/cpp/hook/bytehook_runtime.cpp` — the soft
   load + why it exists.

That's it. Good luck.
