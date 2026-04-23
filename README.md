# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight Android SDK that monitors **all network traffic** in the embedding app — including Java and C++ (NDK) layers — without requiring a VPN or root access. Works on Android phones / tablets and **Android Automotive** / OEM car head-units where `VpnService` is typically unavailable.

## How It Works

NetScope uses **pure GOT / PLT hooking** via [bytehook](https://github.com/bytedance/bhook) (battle-tested in TikTok / Douyin). Every loaded library's GOT entries for a handful of libc network functions are redirected through NetScope's counters.

- **MANUAL mode, no `BYTEHOOK_CALL_PREV` in proxies** → bytehook's AUTOMATIC-mode `bh_trampo_alloc` → `mmap(PROT_EXEC)` code path is structurally unreachable, keeping NetScope W^X-compatible on locked-down ROMs (HMS / HONOR / Knox / IVI head-units)
- **Calls to the real libc go through `dlsym(RTLD_NEXT)` cached pointers** — never chains back into whatever hook the host app (or a vendor library) may have installed first (prevents the classic "`pc == x8`, fault addr in `[anon:libc_malloc]`" crash)
- **Handles `extractNativeLibs="false"`** — bytehook's ELF parser correctly resolves GOT addresses for libraries mapped directly out of `base.apk`, which earlier hookers got wrong on some OEM ROMs. See [`docs/HOOK_EVOLUTION.md`](docs/HOOK_EVOLUTION.md) for the full backstory.
- **`libbytehook.so` is `dlopen`'d on demand, not linked** — since 2026-04-23 `libnetscope.so` lists zero third-party `DT_NEEDED` entries. bytehook (and its transitive `libshadowhook.so`) is mapped only the first time `NetScope.init()` actually needs it, **never** in `DEBUG_ULTRA_MINIMAL` mode. Prevents bytehook / shadowhook static constructors from firing before the SDK knows whether the host process is known-incompatible (e.g. HONOR AGM3-W09HN / EMUI 11).
- Domains are attributed via three signals:
  1. **TLS SNI** — parsed from the ClientHello plaintext
  2. **HTTP Host header** — read from plaintext HTTP
  3. **DNS cache** — `getaddrinfo` is hooked to build an IP → domain map

```
          Java HTTPS / OkHttp              NDK C++ / plaintext HTTP
                  │                                  │
                  ▼                                  ▼
        ┌─────────────────────────────────────────────────────┐
        │  GOT patches in EVERY loaded .so                    │
        │  connect / close / getaddrinfo                      │
        │  send / sendto / write / writev                     │
        │  recv / recvfrom / read / readv                     │
        └────────────────────────┬────────────────────────────┘
                                 ▼
                   FlowTable       (per-fd byte counters + incremental reporting)
                   DnsCache        (IP → domain, 60 s TTL)
                   StatsAggregator (per-domain atomic counters)
                                 │
                                 ▼
                   NetScope Kotlin API
                   ( getDomainStats / getHookReport / LogcatReporter )
```

## Requirements

| Item | Requirement |
|------|-------------|
| Android API | 29+ (Android 10) |
| ABI | arm64-v8a, armeabi-v7a |
| NDK | r25c (25.2.9519653) |
| AGP | 7.4+ |
| Kotlin | 1.6+ |

## Integration

### Option A — JitPack (recommended)

**Step 1.** Add JitPack to your `settings.gradle`:

```groovy
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }   // add this
    }
}
```

**Step 2.** Add the dependency to your module's `build.gradle`:

```groovy
dependencies {
    implementation 'com.github.Arrowyi:NetScope:<latest-commit>'
}
```

Replace `<latest-commit>` with the [latest short commit SHA](https://github.com/Arrowyi/NetScope/commits/main) or a tag from [Releases](https://github.com/Arrowyi/NetScope/releases).

### Option B — Local AAR

Download `netscope-sdk-release.aar` from [Releases](https://github.com/Arrowyi/NetScope/releases) and drop it in `libs/`:

```groovy
dependencies {
    implementation files('libs/netscope-sdk-release.aar')
    implementation 'androidx.annotation:annotation:1.7.1'
    // Bytehook ships libbytehook.so, loaded at runtime by libnetscope.so.
    // When you use the JitPack/Maven dependency above, this is pulled
    // in automatically; with a local AAR you MUST add it explicitly.
    implementation 'com.bytedance:bytehook:1.1.1'
}
```

## Quick Start

### 1. Initialize and observe health in `Application.onCreate()` (or a foreground Service)

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // OPTIONAL: observe status transitions so your HMI / crashlytics
        // can reflect whether traffic monitoring is actually running.
        NetScope.setStatusListener { report ->
            when (report.status) {
                Status.ACTIVE   -> Log.i("NetScope", "monitoring active")
                Status.DEGRADED -> Log.w("NetScope", "partial: ${report.failureReason}")
                Status.FAILED   -> Log.e("NetScope", "disabled: ${report.failureReason}")
                Status.NOT_INITIALIZED -> { /* before init() */ }
            }
        }

        val status = NetScope.init(this)
        if (status != Status.FAILED) {
            // Print a traffic report to Logcat every 30 seconds (tag: NetScope)
            NetScope.setLogInterval(30)
        }
    }
}
```

### 2. Query statistics anywhere

```kotlin
// Cumulative stats since init / last clearStats().
// In-flight long-lived connections are flushed automatically on each call,
// so TCP keep-alives / HTTP/2 persistent connections are counted even
// before they close.
val stats: List<DomainStats> = NetScope.getDomainStats()
stats.forEach { s ->
    Log.i("Traffic", "${s.domain}  ↑${s.txBytesTotal}B  ↓${s.rxBytesTotal}B")
}

// Last completed interval (since last markIntervalBoundary()).
val interval: List<DomainStats> = NetScope.getIntervalStats()
```

### 3. Flow-end callback

```kotlin
NetScope.setOnFlowEnd { stats ->
    // Called each time a TCP connection closes.
    // stats.txBytesInterval / rxBytesInterval = bytes for that single connection.
    Log.d("NetScope", "Closed: ${stats.domain} ↑${stats.txBytesInterval}B ↓${stats.rxBytesInterval}B")
}
```

## Traffic Monitoring Health

Not every device / host app combination is perfectly hookable. NetScope reports its own health so the integrator can surface it to the user instead of silently showing empty data.

```kotlin
val report = NetScope.getHookReport()
// report.status: ACTIVE / DEGRADED / FAILED / NOT_INITIALIZED
// report.isCollecting: convenience bool (ACTIVE or DEGRADED)
// report.connectOk / dnsOk / sendRecvOk / closeOk: per-hook booleans
// report.libcResolved: false if dlsym for any libc symbol failed
// report.failureReason: short string when not ACTIVE, e.g.
//   "SIGSEGV during bytehook_hook_all (possible W^X or vendor-lib GOT layout issue)"
//   "partial hooks: connect=ok dns=FAIL send_recv=ok close=ok libc=11/11"
//   "bytehook_init returned 11 (INITERR_CFI) — check W^X policy / kernel mmap"
```

### When will you see `DEGRADED` / `FAILED`?

| Condition | Status |
|---|---|
| Everything installed cleanly and the post-install audit confirmed every GOT write went to a real GOT slot | `ACTIVE` |
| One of the `install_hook_*` calls failed but others succeeded | `DEGRADED` |
| `bytehook_init` failed. In MANUAL mode the common smoking gun is `INITERR_CFI` — bytehook could not `mprotect(PROT_WRITE)` another library's `.text` to disable CFI on an SELinux `execmod`-strict kernel. (`INITERR_TRAMPO` / `INITERR_HUB` only appear if we ever accidentally flip to AUTOMATIC mode — they'd be a NetScope regression, not a platform issue.) | `FAILED` |
| SIGSEGV during initial hook install → SDK rolled back, host app keeps running | `FAILED` |
| A critical libc symbol (connect / send / recv / read) failed to resolve via dlsym | `FAILED` |
| **Post-install audit detected GOT writes landing in non-executable memory** (`auditSlotsCorrupt > 0`, see below) | `FAILED` |

When the status is `FAILED`, NetScope's hook handlers short-circuit and stop collecting data, bytehook is told to unhook every stub it installed, and your app's network calls continue to work as if NetScope weren't there.

### Post-install GOT audit

Right after the initial hook install, NetScope walks every loaded `.so` via `dl_iterate_phdr`, reads the actual GOT entry for each of the ~11 libc symbols we patch, and classifies what the GOT currently holds. A slot's value is matched **exactly** against the set of pointers we passed to `bytehook_hook_all()`:

| Audit bucket | Meaning |
|---|---|
| `auditSlotsHooked`   | GOT value exactly equals a NetScope stub pointer — correct. |
| `auditSlotsUnhooked` | GOT still holds the real libc pointer — that lib was excluded or loaded too late. Benign. |
| `auditSlotsChained`  | GOT points into some other library's executable region — a third-party hooker got there first. Not a crash. |
| `auditSlotsCorrupt`  | **GOT points into `rw-p` data / unmapped memory** — the hooker wrote to a non-executable page and this slot would crash on call. **Forces `FAILED` + rollback.** |
| `auditHeapStubHits`  | Advisory / diagnostic only. Counts how many copies of NetScope stub pointers are sitting inside `[anon:libc_malloc]` pages. **This does NOT force `FAILED`** — legitimate copies are expected (bytehook's internal registry, bionic's sigaction handler table, soinfo / dl_phdr_info snapshots). |

Only `auditSlotsCorrupt > 0` triggers rollback. When it happens the audit calls `bytehook_unhook()` for every stub NetScope installed, restoring the pre-hook libc pointers into every GOT slot.

## Diagnostic mode (for HMI integration agents)

Most devices stay on `ACTIVE`. A small number of OEM + host-app combinations (notably some HONOR head-units running apps that internally hook libc themselves, e.g. `asdk.httpclient`) still crash some seconds after init even though the post-install GOT audit passes. When triaging such a device, enable diagnostic flags **before** `init()`:

```kotlin
// ONE LINE added in your Application.onCreate(), BEFORE NetScope.init().
// The flags are additive — OR them together.
NetScope.setDebugMode(
    NetScope.DEBUG_TRACE_HOOKS   // log every GOT write + warn on CONTESTED slots
    or NetScope.DEBUG_SKIP_HOOKS // init bytehook but register no stubs
)
NetScope.init(this)
```

### Flags

| Flag | Effect | Safe for production? |
|---|---|---|
| `DEBUG_NONE` | Default. No extra logs. | ✔ |
| `DEBUG_TRACE_HOOKS` | For each GOT write bytehook performs, log `{caller_lib, symbol, prev_func, new_func}`. If `prev_func` doesn't match the `dlsym(RTLD_NEXT)`-resolved real libc pointer, log `CONTESTED` — another PLT/GOT hooker was already active in that library. Also turns on bytehook's own `debug` stream (tag `bytehook`) and `bytehook_set_recordable(true)`. Additionally snapshots `/proc/self/maps` + 32 bytes at well-known libc/libdl entry points (including `__cfi_slowpath`) BEFORE and AFTER `bytehook_init`, logging any VMA or byte-level diff as `init-diff: ...`. | ✔ (verbose logs only) |
| `DEBUG_SKIP_HOOKS` | `bytehook_init` still runs (CFI disable, shadowhook trampoline registration, the whole load path) — but NetScope installs ZERO stubs. `HookReport.status = DEGRADED`, `failureReason = "diagnostic: DEBUG_SKIP_HOOKS — bytehook initialised (...), no stubs registered"`. **Traffic is NOT collected.** | ✖ diagnostic only |
| `DEBUG_ULTRA_MINIMAL` | Most aggressive. Resolves libc via `dlsym(RTLD_NEXT)` (passive; no writes) **and does not load `libbytehook.so` at all**. Combined with the fact that `libbytehook.so` is no longer in `libnetscope.so`'s `DT_NEEDED` (since 2026-04-23, see `docs/HOOK_EVOLUTION.md`), this means neither `libbytehook.so` nor `libshadowhook.so` are ever mapped into the process. `HookReport.status = DEGRADED`, `failureReason = "diagnostic: DEBUG_ULTRA_MINIMAL — libc resolved (N/11) but bytehook_init NOT called"`. Verify with `adb shell "grep -E 'libbytehook\|libshadowhook' /proc/\$(pidof <app>)/maps"` — expected output is empty. **Traffic is NOT collected.** | ✖ diagnostic only |

### Recommended recipe for a crashing device

Ship ONE APK with a build-config toggle so QA can flip between these modes at runtime (e.g. via a hidden developer-options switch) and collect logcat for each. Walk the ladder from "most-like-production" to "literally nothing":

1. **Build A — trace everything.** `setDebugMode(DEBUG_TRACE_HOOKS)`. All hooks installed plus full before/after diff. Grep logcat for:
   - `bytehook-trace: CONTESTED ...` — another hooker got to a library first.
   - `init-diff: ... CHANGED` — specific byte sequences that bytehook's init rewrote; usually the only expected hit is `libdl.so!__cfi_slowpath`. Anything else changing (e.g. `libart.so` symbols) is a shadowhook pattern-match misfire — file the line back.
   - `init-diff: +vma ...` — new `.so` or anon mappings that appeared during init.

2. **Build B — bytehook init only, no writes.** `setDebugMode(DEBUG_SKIP_HOOKS)`. Isolates the bytehook-init side effects (CFI disable, shadowhook trampolines) from NetScope's own GOT writes. If the app crashes here but not in Build A, GOT writes are compensating; usually the other way around.

3. **Build C — do not even load libbytehook.so.** `setDebugMode(DEBUG_ULTRA_MINIMAL)`. The last remaining thing NetScope's runtime does is `dlsym(RTLD_NEXT)` on ~11 libc symbols — pure read-only linker work. Since the 2026-04-23 `DT_NEEDED` strip, this flag additionally skips `System.loadLibrary("bytehook")` and the native `dlopen("libbytehook.so")`, so neither `libbytehook.so` nor `libshadowhook.so` is ever mapped into the process. If the app STILL crashes in this mode, NetScope's *runtime* is not the trigger **and** neither is bytehook's load path — the culprit is static-init code that merely loading `libnetscope.so` (which now has zero third-party `DT_NEEDED` entries) brings into the process, or a side effect from the `dlsym` calls themselves.

4. **Build D — trace + minimal.** `setDebugMode(DEBUG_TRACE_HOOKS or DEBUG_ULTRA_MINIMAL)`. Enables the VMA + byte-probe diff in Build C mode, so you can see what (if anything) merely *loading* the SDK does to `/proc/self/maps` vs. what `bytehook_init` adds on top.

### What the HMI agent should collect

For each build, capture:
- `adb logcat -s NetScope:V bytehook:V AndroidRuntime:E DEBUG:E` for ~30 s after app launch
- `NetScope.getHookReport()` snapshot at +5 s, +15 s, +30 s (status, slot counts, failureReason)
- Full tombstone if a native crash occurs (`/data/tombstones/tombstone_*`)

The logs that pin the root cause look like:

```
W NetScope: bytehook-trace: CONTESTED lib=/data/app/.../libasdk_httpclient.so sym=send  \
            prev=0x7a82310080 (!= real libc=0x7af4a0d120) new=0x7a7f2efca0 \
            — another hooker was already active in this library
```

A line like that, immediately followed by a tombstone in that same library's thread, is conclusive evidence for Build A's hooker-conflict hypothesis.

And an `init-diff` line showing a byte mismatch outside `libdl.so!__cfi_slowpath` looks like:

```
W NetScope: init-diff: libart.so!art_jni_dlsym_lookup_stub @ 0x789c0a14c0 CHANGED
W NetScope: init-diff:   before: fd 7b bf a9 fd 03 00 91 ff 43 01 d1 e0 03 00 aa ...
W NetScope: init-diff:   after : 00 02 00 d4 ff 43 01 d1 e0 03 00 aa 00 00 00 00 ...
```

The first four bytes changing to `00 02 00 d4` (an `SVC #0x10` / `BRK` sequence) would be conclusive evidence that bytehook's shadowhook backend patched an ART internal function it shouldn't have — file the line back and we will investigate a PLT-only backend.

### Turning diagnostic mode off

Ship subsequent production builds with `setDebugMode(NetScope.DEBUG_NONE)` (or just remove the call entirely — `DEBUG_NONE` is the default). `DEBUG_SKIP_HOOKS` MUST NOT leak into production: no traffic is collected while it is set.

## Known incompatible hosts

Some device + host-app combinations crash the host process even when NetScope is configured so that it does literally nothing at runtime beyond `dlsym(RTLD_NEXT)` on 11 libc symbols. The crash is proven **not** to originate in NetScope itself; it is triggered by some side effect of merely having `libnetscope.so` present in the process and/or by the 11 passive `dlsym` calls interacting with a host-app native hooker.

| Device / ROM | Host app / thread | Crash | Investigation verdict |
|---|---|---|---|
| HONOR AGM3-W09HN · EMUI 11 / Magic UI 4.0 · MTK Helio P65 | Telenav-based navigator, `asdk.httpclient` thread | `SIGSEGV`, fault addr ∈ `[anon:libc_malloc]`, abort `"create DR Engine success"`, bit-identical register fingerprint across runs (same `x17` low 12 bits, same `pc == x8`) | Reproduced on `b500638` with `DEBUG_ULTRA_MINIMAL` — `libbytehook.so` / `libshadowhook.so` verified absent from `/proc/<pid>/maps`, `HookReport.hooked == 0` for the entire app lifetime. SDK contact surface already at theoretical minimum; trigger lives in the host app. See `docs/HOOK_EVOLUTION.md` "2026-04-23 — Final verdict on b500638" for the full writeup. |

**Recommended integrator workarounds** on the affected SKU:

1. **Preferred.** Gate `NetScope.init()` behind a `Build.MODEL` / `Build.MANUFACTURER` allow-list and skip it entirely on the known-bad combination. This keeps the SDK out of the process and is guaranteed safe.
2. **Deferred init.** Move `NetScope.init()` out of `Application.onCreate()` into a foreground-service `onCreate` that starts only once the host has finished its warm-up. If hypothesis #1 in the HOOK_EVOLUTION writeup is correct (a pre-existing host-app native hooker whose layout is sensitive to how many `.so`'s are loaded ahead of the "DR Engine" boot), delaying `libnetscope.so` past that boot window should avoid the trigger. Unverified on HONOR AGM3-W09HN; worth trying before option #1 if the business wants traffic stats on that SKU.
3. **Degraded-collection fallback.** Ship with `setDebugMode(DEBUG_ULTRA_MINIMAL)` on the bad SKU. NetScope is inert (no traffic collected), but we have full evidence the crash still reproduces in this mode, so this is **not** a workaround — it's only useful as "proof the SDK is not at fault" when an integrator needs to demonstrate that to a vendor.

If you reproduce a similar pattern on a different device, please file a ticket with:

* `adb shell getprop | grep -E 'build\.(fingerprint|product|display|version)'`
* `grep -E '<your-app-lib>\.so|libasdk' /proc/<pid>/maps` sample
* Three tombstones from independent runs (we look at whether `x17` is identical — same bits = deterministic hook site, not corruption)

## API Reference

### `NetScope` (object)

| Method | Description |
|--------|-------------|
| `init(context): Status` | Install PLT hooks and start monitoring. Idempotent. Returns the SDK's health. |
| `pause()` | Suspend byte counting (hooks remain installed). |
| `resume()` | Resume byte counting after `pause()`. |
| `destroy()` | Uninstall all hooks and release resources. |
| `clearStats()` | Reset all counters. Hooks unaffected. |
| `markIntervalBoundary()` | Flush in-flight flows, snapshot current-interval counters, start a new interval. |
| `getDomainStats(): List<DomainStats>` | Cumulative stats, sorted by total bytes desc. Flushes in-flight flows before returning. |
| `getIntervalStats(): List<DomainStats>` | Last completed interval stats, sorted by interval bytes desc. |
| `setLogInterval(seconds: Int)` | Start periodic Logcat report (tag `NetScope`). Pass `0` to stop. |
| `setOnFlowEnd(callback?)` | Register per-connection close callback. Pass `null` to clear. |
| `getHookReport(): HookReport` | Snapshot the current hook health. |
| `setStatusListener(callback?)` | Get notified on every status transition. |
| `setDebugMode(flags: Int)` | Set diagnostic flags. **Must** be called before `init()`. See "Diagnostic mode" above. Pass `DEBUG_NONE` (default) in production. |

### `Status` (enum)

| Value | Meaning |
|---|---|
| `NOT_INITIALIZED` | `init()` hasn't been called (or was rolled back) |
| `ACTIVE`          | All hooks installed, full data |
| `DEGRADED`        | Some hooks missing; partial data |
| `FAILED`          | Critical failure; no data will be collected |

### `HookReport` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `status` | `Status` | See above |
| `isCollecting` | `Boolean` | `true` iff `ACTIVE` or `DEGRADED` |
| `libcResolved` | `Boolean` | All critical libc symbols resolved via dlsym |
| `connectOk` / `dnsOk` / `sendRecvOk` / `closeOk` | `Boolean` | Per-hook registration success |
| `failureReason` | `String?` | Empty when `ACTIVE`; short machine-readable reason otherwise |

### `DomainStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Domain name (or IP if resolution failed) |
| `txBytesTotal` | `Long` | Cumulative bytes sent |
| `rxBytesTotal` | `Long` | Cumulative bytes received |
| `txBytesInterval` | `Long` | Bytes sent in current/last interval |
| `rxBytesInterval` | `Long` | Bytes received in current/last interval |
| `connCountTotal` | `Int` | Total **closed** connections (does not increment for still-open keep-alive flows) |
| `connCountInterval` | `Int` | Connections closed in current/last interval |
| `lastActiveMs` | `Long` | Timestamp of last activity (steady clock ms) |
| `totalBytes` | `Long` | Computed: `txBytesTotal + rxBytesTotal` |

## Logcat Output Format

```
I NetScope: ══════ Traffic Report [2026-04-23 12:00:00] ══════
I NetScope: ── Interval ──────────────────────────────
I NetScope:   api.github.com                           ↑1.2 KB    ↓45.6 KB   conn=3
I NetScope:   www.google.com                           ↑0.8 KB    ↓12.1 KB   conn=1
I NetScope: ── Cumulative ────────────────────────────
I NetScope:   api.github.com                           ↑8.4 KB    ↓312.0 KB  conn=21
I NetScope:   www.google.com                           ↑3.2 KB    ↓88.7 KB   conn=7
I NetScope: ═════════════════════════════════════════
```

Diagnostic `DEBUG` lines are also emitted each report cycle:

```
D NetScope: flow-table: flush_in_flight flows=2 tx=14832 rx=8124
D NetScope: stats: markIntervalBoundary records=3 non_zero=2
D NetScope: report raw interval=2 cumulative=3
```

## Why won't my host app crash this time?

Earlier builds of NetScope (xhook era) relied on the hooker's `orig_*` out-parameter to call "whatever function was in this GOT before we patched it". When the host app (or a third-party native library inside it — e.g. custom HTTP stacks, vendor telematics libs) had already installed its own hooks on `connect` / `send` / etc., that `orig_*` pointer landed inside the third party's trampoline, whose private state could be stale or freed, producing `SIGSEGV SEGV_ACCERR` with `pc == x8` pointing into `[anon:libc_malloc]`.

NetScope now **always calls the real libc** via `dlsym(RTLD_NEXT)` cached pointers, so it no longer chains into any other hooker's trampoline. GOT patches still observe traffic, but the "call original" arrow short-circuits straight to libc. We explicitly do **not** use `BYTEHOOK_CALL_PREV` in any proxy — that macro requires a shared trampoline page that strict-W^X kernels refuse.

Additionally, the initial hook install is wrapped in a thread-local `sigsetjmp` / `SIGSEGV` handler: if bytehook ever segfaults on a pathological vendor library, NetScope unhooks every stub it installed, flips status to `FAILED`, and the host app keeps running. The `SIGSEGV` handler chains back to the host's original signal handler for any segfault that isn't ours, so you don't lose tombstones from genuine app crashes.

For the full evolution of the crash scenarios we've mitigated (shadowhook W^X → bhook W^X → xhook `orig_*` crash → xhook APK-embedded misroute → bytehook 1.1.1), read [`docs/HOOK_EVOLUTION.md`](docs/HOOK_EVOLUTION.md).

## Known Limitations

### Environmental

- **Locked-down W^X kernels** (some IVI head-units, certain Knox-derived ROMs): NetScope runs bytehook in `MANUAL` mode and never calls `BYTEHOOK_CALL_PREV`, so the AUTOMATIC-mode trampoline allocator (`bh_trampo_alloc` → `mmap(PROT_EXEC)`) is structurally unreachable. The only W^X-related failure path left is `INITERR_CFI` — bytehook calls `mprotect(PROT_WRITE)` on another library's `.text` page to patch out a CFI check, and strict `execmod` SELinux policy can deny that. NetScope surfaces the numeric status code in `failureReason` so the HMI can distinguish it from any other init failure. If you hit `INITERR_CFI` on a device you control, please file an issue — we can evaluate running without CFI-disable (at the cost of losing hooks for CFI-enabled callers), or writing our own minimal PLT patcher (we already parse ELF in `got_audit.cpp`).
- **`extractNativeLibs="false"` on HONOR Android 10** (historical): xhook 1.2.0 mis-computed GOT addresses for `base.apk!/lib/...` layouts. Bytehook handles these correctly, so this limitation is no longer applicable.
- `auditHeapStubHits > 0` on its own is **not** a failure. It's an advisory count of NetScope stub pointers observed inside `[anon:libc_malloc]` pages. Legitimate copies are expected (bytehook maintains an internal task registry; bionic keeps our SIGSEGV guard in its sigaction table; the dynamic linker stores library load-base values in several places). The authoritative failure signal is `auditSlotsCorrupt > 0`.

### Functional

- **Per-connection count for open flows**: `connCountTotal` only counts **closed** connections. Long-lived TCP keep-alive / HTTP/2 streams show `conn=0` until they close, even though their bytes are counted.
- **Custom close paths**: `close_range()` / `__close()` / `dup2()` on an active fd won't trigger our `close` hook. Byte counters remain correct (bytes are flushed per interval), but the corresponding `connCount` won't increment.
- **Static-linked libc**: The extremely rare `.so` that statically links libc cannot be hooked via PLT.
- **Single process**: Monitoring is limited to the app process in which the SDK is initialized.

## Build from Source

```bash
git clone git@github.com:Arrowyi/NetScope.git
cd NetScope
./gradlew :netscope-sdk:assembleRelease
# AAR output: netscope-sdk/build/outputs/aar/netscope-sdk-release.aar
```

NDK r25c is downloaded automatically by Gradle. No manual NDK installation required.

## License

```
Copyright 2025 Arrowyi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
