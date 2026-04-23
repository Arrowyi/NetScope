# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight Android SDK that monitors **all network traffic** in the embedding app — including Java and C++ (NDK) layers — without requiring a VPN or root access. Works on Android phones / tablets and **Android Automotive** / OEM car head-units where `VpnService` is typically unavailable.

## How It Works

NetScope uses **pure GOT / PLT hooking** via [xhook](https://github.com/iqiyi/xHook) (statically linked into `libnetscope.so`, no extra `.so` shipped). Every loaded library's GOT entries for a handful of libc network functions are redirected through NetScope's counters.

- **No trampolines, no `mmap(PROT_EXEC)`** → works on strict-W^X ROMs (HMS / HONOR / some Knox builds)
- **Calls to the real libc go through `dlsym(RTLD_NEXT)` cached pointers** — never chains back into whatever hook the host app may have installed first (prevents the classic "`pc == x8`, fault addr in `[anon:libc_malloc]`" crash)
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
}
```

NetScope has **no transitive native dependency** — xhook is statically linked into `libnetscope.so`.

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
//   "SIGSEGV during xhook_refresh ..."
//   "partial hooks: connect=ok dns=FAIL send_recv=ok close=ok libc=12/12"
```

### When will you see `DEGRADED` / `FAILED`?

| Condition | Status |
|---|---|
| Everything installed cleanly | `ACTIVE` |
| One of the `xhook_register` calls failed but others succeeded | `DEGRADED` |
| A runtime `dlopen` triggered an xhook refresh that crashed (rare, vendor-specific GOT layouts) — SDK rolled back, host app keeps running | `DEGRADED` |
| `xhook_refresh` crashed during initial install → fully rolled back | `FAILED` |
| A critical libc symbol (connect / send / recv / read) failed to resolve via dlsym | `FAILED` |

When the status is `FAILED`, NetScope's hook handlers short-circuit and stop collecting data, but your app's network calls continue to work as if NetScope weren't there.

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

Earlier builds of NetScope relied on xhook's `orig_*` out-parameter to call "whatever function was in this GOT before we patched it". When the host app (or a third-party native library inside it — e.g. custom HTTP stacks, vendor telematics libs) had already installed its own hooks on `connect` / `send` / etc., that `orig_*` pointer landed inside the third party's trampoline, whose private state could be stale or freed, producing `SIGSEGV SEGV_ACCERR` with `pc == x8` pointing into `[anon:libc_malloc]`.

NetScope now **always calls the real libc** via `dlsym(RTLD_NEXT)` cached pointers, so it no longer chains into any other hooker's trampoline. GOT patches still observe traffic, but the "call original" arrow short-circuits straight to libc.

Additionally, `xhook_refresh` (both the initial install and any dlopen-triggered refresh) is wrapped in a thread-local `sigsetjmp` / `SIGSEGV` handler: if xhook ever segfaults on a pathological vendor library, NetScope rolls back, flips status to `FAILED`, and the host app keeps running. The `SIGSEGV` handler chains back to the host's original signal handler for any segfault that isn't ours, so you don't lose tombstones from genuine app crashes.

## Known Limitations

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
