# Native-Hook Postmortem (Bytehook Era)

> **Status: RETIRED, 2026-04-24.** NetScope no longer uses any native
> hooking backend. This document exists so the next person who proposes
> "let's hook libc at runtime" has a single, short place to read what
> happens when you try. **Read this first.** Then [HOOK_EVOLUTION.md](HOOK_EVOLUTION.md)
> if you want the 494-line chronological deep dive.
>
> The short version: on real IVI / OEM Android head-units, the mere
> *presence* of a native PLT hooker in the process — even configured to
> do absolutely nothing — is enough to destabilise host apps whose own
> native stacks already contain their own hookers or have unconventional
> ELF layouts. Two independent devices (HONOR AGM3-W09HN, Chery 8155)
> on the exact same `libFoundationJni.so` build proved this beyond any
> reasonable doubt. See §5 below.

---

## 1. Timeline, condensed

| Order | Backend              | Shipped         | Killed by                                      |
|-------|----------------------|-----------------|------------------------------------------------|
| 1     | shadowhook 1.0.9     | earliest alpha  | inline-hook trampolines need `mmap(PROT_EXEC)` |
| 2     | shadowhook 2.0.0     | `22bc487`       | same W^X problem on HONOR Android 10           |
| 3     | bytehook 1.1.1 (AUTO) | `eeaf53f`      | AUTOMATIC mode + `BYTEHOOK_CALL_PREV` → `bh_trampo_alloc` → `mmap(PROT_EXEC)`; dies on W^X ROMs |
| 4     | xhook 1.2.0          | `8934473`       | mis-computes GOT addresses for APK-embedded `.so`, stubs land in `[anon:libc_malloc]` |
| 5     | bytehook 1.1.1 (MANUAL) | `68acdfb`    | **Shipped, stable on most devices**, but still crashes some OEM hosts at SDK load time even with zero hooks installed. Retired. |

Every backend switch felt like "finally got it right". Every backend then exposed a new failure mode on a new device. The pattern was stable enough to formalise:

> **Any PLT/GOT hooker, in any mode, in an IVI process, is a permanent
> liability. The load-time footprint alone — bytehook + shadowhook
> constructors, libshadowhook's `mprotect(PROT_WRITE)` on `libdl.so` to
> disable CFI — is enough to poison a subset of devices.**

---

## 2. The seven classes of problem we hit

Dense version. Each is expanded in [HOOK_EVOLUTION.md](HOOK_EVOLUTION.md).

**P1. W^X on locked-down kernels.** `mmap(PROT_EXEC)` returns EPERM or the allocator falls back to malloc and the kernel kills on first execute. Triggered by shadowhook (inline) and bytehook AUTOMATIC (trampoline page). Mitigated by forcing bytehook `MODE_MANUAL` + never calling `BYTEHOOK_CALL_PREV`.

**P2. `orig_*` chains into host-app hooker.** The hooker-returned "previous function" pointer lands inside a third party's trampoline. When that third party's internal state is stale/freed, we get `SIGSEGV SEGV_ACCERR` with `pc == x8` pointing into `[anon:libc_malloc]`. Mitigated by always resolving real libc via `dlsym(RTLD_NEXT)` ourselves and never touching `orig_*` / `CALL_PREV`.

**P3. `extractNativeLibs="false"`.** xhook 1.2.0 mis-parsed `base.apk!/lib/...` layouts, wrote GOT stubs to arbitrary addresses. Bytehook fixed this in its own ELF parser.

**P4. Audit rollback on false positives.** The post-install GOT audit classified legitimate stub copies (bytehook's own task registry, bionic sigaction table, soinfo snapshots) as "corrupt", forcing a rollback even when hooks were healthy. Mitigated by switching `heap-stub-hits > 0` from fatal to advisory; only `slots_corrupt > 0` is fatal.

**P5. Dereferencing unsafe anon memory.** Early audit code walked every `rw-p anon:*` region and dereferenced. Android Q+ tags many anons (`[anon:scudo_*]`, `[anon:scs:*]`, `[anon:cfi shadow]`) that are VA-reserved but not page-backed. Mitigation: only walk `[anon:libc_malloc]`.

**P6. Empty interval stats for keep-alive / HLS.** `FlowTable` didn't flush in-flight bytes at interval boundary, so long-lived streams showed zero bytes. Mitigation: `flush_in_flight()` before every read + boundary mark.

**P7. `libbytehook.so` in `DT_NEEDED`.** Bytehook/shadowhook static constructors fire at `System.loadLibrary("netscope")` time, before we know whether the host is known-incompatible. Fatal on HONOR AGM3-W09HN. Mitigation: `dlopen` bytehook lazily, only from `NetScope.init()` after diagnostic flags are checked.

**P8 (implicit).** The presence of the SDK's `.so` footprint in the APK — even when the SDK runtime does literally nothing beyond 11 passive `dlsym(RTLD_NEXT)` calls — is itself a destabiliser on some hosts. This is what finally killed the native approach: §5 below.

---

## 3. Golden rules (as decided lessons)

If a future maintainer ever re-introduces native hooking, these are non-negotiable. Skipping any of them guarantees re-hitting a specific problem from §2.

| # | Rule | Protects against |
|---|---|---|
| G1 | Never call `orig_*` / `BYTEHOOK_CALL_PREV`. Always resolve real libc via `dlsym(RTLD_NEXT)`. | P2 |
| G2 | Exact-match stub identity, no range checks. | P4 |
| G3 | Only dereference `[anon:libc_malloc]`. | P5 |
| G4 | `heap-stub-hits > 0` is advisory; only `slots_corrupt > 0` is fatal. | P4 |
| G5 | Every failure path surfaces a human-readable `failureReason`. | debuggability |
| G6 | Bytehook ALWAYS in `MODE_MANUAL`. Never AUTOMATIC without a W^X-safe `bh_trampo_alloc` replacement. | P1 |
| G7 | `libbytehook.so` out of `DT_NEEDED`. Use `dlopen` + `dlsym`. | P7 |
| G8 | Kotlin static initialiser loads ONLY `netscope`. Bytehook load is a late, guarded call. | P7 |
| G9 | Every `register_stub()` mirrored in the audit's symbol list. | undetected corruption |
| G10 | Any long-lived reporter calls `flush_in_flight()` first. | P6 |
| G11 | Hook install wrapped in `sigsetjmp` + per-thread guard. Don't remove. | P2 on pathological libs |

---

## 4. Failure-mode fingerprints (quick triage)

| Pattern | Meaning |
|---|---|
| `pc == x8` and fault addr ∈ `[anon:libc_malloc]` | A dispatch target in a heap trampoline that is no longer valid — another hooker got to the GOT first. Not us. |
| Identical `x17` low 12 bits across multiple PIDs in one boot | Deterministic call site, not corruption. Walk the `DEBUG_SKIP_HOOKS` → `DEBUG_ULTRA_MINIMAL` ladder. |
| Tombstone inside `libasdk_httpclient.so` sometime 10–60 s after `NetScope.init()` on an affected SKU | **The fingerprint that killed the native approach.** See §5. |

---

## 5. The experiment that ended it (2026-04-23)

Two devices, both running the same Telenav navigator with the same `libFoundationJni.so` (MD5 `02cd184e930f63c7bc26fb32e2452e7e`):

| Device | NetScope state | Runtime | Crashes |
|---|---|---|---|
| HONOR AGM3-W09HN (Android 10) | `:netmonitor` *dependency absent from APK* | 540 s | 0 |
| HONOR AGM3-W09HN             | dep present + `DEBUG_ULTRA_MINIMAL` (runtime inert) | ~10 min | 6 same-fingerprint tombstones |
| HONOR AGM3-W09HN             | dep present + dlopen load-only | 90 s | almost every run |
| HONOR AGM3-W09HN             | dep present + init deferred 60 s (D60) | 90 s | crashes *before* dlopen in 2/3 runs |
| Chery 8155 (Android 11)      | `libnetscope.so` statically in APK + kill-switch | 180 s | 7 |
| Chery 8155                   | `libnetscope.so` stripped from APK (stub stand-in) + kill-switch | 540 s | 0 |

Interpretation, short:

1. **Root cause lives in Telenav's C++ stack**, not in NetScope. A pre-existing `ClientImpl` / `Session` session-level race in `asdk.httpclient` fires during a 10–60 s boot window.
2. **NetScope's *runtime* is not the trigger.** D60 proves this: the crash happens *before* we even `dlopen` bytehook.
3. **NetScope's *static footprint* is the amplifier.** Just 4 `.so` files, ~16 Java classes, an AndroidX Startup meta-data entry, and a ~1.5 MB right-shift of the APK central directory changed the race's outcome from "never fires" to "always fires" on two independent device models.
4. Therefore: **the SDK's theoretical-minimum contact surface was already at fault.** There is no more shrinking to do in the native world.

HMI's conclusion, adopted as our reality: the native approach costs us real crashes on real customer devices and buys us only what a Java-layer AOP implementation can match. Retired.

---

## 6. What we gained along the way (and kept)

Not everything from the native era is thrown out. Lessons we carry forward:

- **Per-domain counters, interval snapshots, flow-end callbacks** as a data model. The Kotlin `TrafficAggregator` preserves the semantics of `StatsAggregator` + `FlowTable.flush_in_flight` without the fd bookkeeping.
- **Marker-based idempotency** (the equivalent of `hook_stubs.cpp` exact-match). Every NetScope wrapper implements `NetScopeInstrumented` so no object ever gets wrapped twice, even when the build-time instrumentation and manual wiring both fire.
- **Never a silent-degrade contract.** Status is public and honest; `DEGRADED` / `FAILED` no longer exist only because the AOP world has no equivalent failure mode, not because we've softened the policy.
- **Document every abandoned path.** This doc, plus the full chronicle in [HOOK_EVOLUTION.md](HOOK_EVOLUTION.md), exists because future-us will re-propose one of these otherwise.

---

## 7. If you must re-propose native hooks

Before writing code, answer all of these with evidence:

1. What device surfaced a new gap that Java AOP cannot close?
2. Have you reproduced that gap three times with identical fingerprint?
3. Does the target host have its own native hooker? (Run `grep -E 'bytehook|shadowhook|xhook|frida' /proc/<pid>/maps`.)
4. What is your plan for the HONOR AGM3-W09HN / Chery 8155 class of device — where the SDK's static footprint is the trigger regardless of runtime?
5. Which of G1–G11 in §3 will your design NOT uphold? (If the answer is "all of them", you are rebuilding NetScope's pre-2026-04-24 state. Read this doc again.)

If you can't answer (4), stop.
