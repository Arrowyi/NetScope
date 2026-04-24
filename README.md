# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight Android SDK that collects **per-domain Java-layer network
traffic statistics** with **zero changes to your application source
code**. Works on phones, tablets, and **Android Automotive** / OEM car
head-units where `VpnService` / root are unavailable.

## How It Works

NetScope uses **build-time AOP (ASM bytecode instrumentation)** via a
Gradle Transform plugin. When you apply `indi.arrowyi.netscope` to your
app module, every call to:

- `OkHttpClient.Builder.build()`
- `HttpsURLConnection.getInputStream()` / `getOutputStream()` (including
  `HttpURLConnection`, `URLConnection`)
- `OkHttpClient.newWebSocket(...)`

is rewritten at compile time to route through lightweight NetScope
wrappers that count bytes per-domain. Your source is untouched.

```
          Java HTTPS / OkHttp              HttpsURLConnection                 OkHttp WebSocket
                  │                                │                                   │
                  ▼                                ▼                                   ▼
        ┌─────────────────────────────────────────────────────────────────────────────────────┐
        │  NetScope Gradle Transform (applied at build time)                                  │
        │  OkHttpClient$Builder.build()     → + NetScopeInterceptor                           │
        │  URLConnection.getInputStream()    → + counting InputStream                         │
        │  OkHttpClient.newWebSocket()       → wrapped listener + wrapped WebSocket           │
        └────────────────────────────────────┬────────────────────────────────────────────────┘
                                             ▼
                   TrafficAggregator (AtomicLong per-domain counters)
                                             │
                                             ▼
                   NetScope Kotlin API
                   ( getDomainStats / getIntervalStats / getTotalStats / setOnFlowEnd )
```

### Scope of observation

NetScope observes **only Java-layer** traffic. Native HTTP clients
(e.g. Telenav `asdk.httpclient`, libcurl via JNI, Chromium / WebView,
raw sockets from NDK code) are invisible to it. Those stacks are
expected to report their own stats; the integrator sums:

```
app_total_traffic  =  NetScope.getTotalStats()  +  <native stack stats>
```

This is a deliberate architectural choice. The previous native-hook
implementation (bytehook / shadowhook) is retired — see
[`docs/BYTEHOOK_LESSONS.md`](docs/BYTEHOOK_LESSONS.md) for the
postmortem. Two independent OEM devices (HONOR AGM3-W09HN, Chery 8155)
proved that even an inert native SDK footprint destabilises certain
host processes. AOP sidesteps the entire class of problem.

### No double counting, no missed flows

Every NetScope wrapper implements a `NetScopeInstrumented` marker
interface. Both the Gradle Transform and the runtime injectors check
for the marker before wrapping, so:

- Manually adding `NetScopeInterceptor` + having the Transform run = 1×
  count (not 2×).
- A `URLConnection` whose stream is already wrapped won't be
  double-wrapped by a nested instrumentation site.
- If a flow goes through multiple layers (e.g. OkHttp on top of a
  wrapped `URLConnection`), only the top-most wrapping counts.

## Requirements

| Item | Requirement |
|------|-------------|
| Android API | 29+ (Android 10) |
| AGP | **4.2.2+** (legacy `Transform` API; AGP 7.x / 8.x also work) |
| Gradle | 6.7.1+ |
| JDK running Gradle | 8+ |
| Kotlin | 1.6.21+ |

## Integration

### Step 1 — Add the plugin classpath

Project-level `build.gradle`:

```groovy
buildscript {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }
    }
    dependencies {
        // groupId is `com.github.Arrowyi.NetScope` (DOT, not colon) —
        // JitPack multi-module convention because both artifacts come
        // from the same repo.
        classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v2.0.0'
    }
}
```

### Step 2 — Apply the plugin and add the runtime dependency

App-module `build.gradle`:

```groovy
apply plugin: 'com.android.application'
apply plugin: 'kotlin-android'
// If you use AspectJ, apply it BEFORE NetScope.
apply plugin: 'indi.arrowyi.netscope'

dependencies {
    implementation 'com.github.Arrowyi.NetScope:NetScope:v2.0.0'
}
```

The `v2.0.0` tag is pinned. For other releases, pick a tag from
[Releases](https://github.com/Arrowyi/NetScope/releases) or an exact
short SHA from
[github.com/Arrowyi/NetScope/commits/main](https://github.com/Arrowyi/NetScope/commits/main).
Avoid `main-SNAPSHOT` in production — JitPack re-resolves it on every
fetch.

### Step 3 — Initialise in `Application.onCreate()`

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)                 // always returns ACTIVE
        NetScope.setLogInterval(30)         // optional periodic report
        NetScope.setOnFlowEnd { stats ->    // optional per-flow callback
            Log.d("NetScope", "${stats.domain} ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
        }
    }
}
```

No changes anywhere else in your app. Your OkHttp clients, URL
connections, and WebSockets are instrumented at build time.

## API Reference

### `NetScope` (object)

| Method | Description |
|--------|-------------|
| `init(context): Status` | Idempotent. Always returns `ACTIVE` in the AOP architecture. |
| `status(): Status` | Current state: `NOT_INITIALIZED` or `ACTIVE`. |
| `pause()` / `resume()` | Suspend / resume counting. Instrumentation stays in place; increments become no-ops while paused. |
| `clearStats()` | Reset all counters. |
| `markIntervalBoundary()` | Freeze current-interval counters into the interval snapshot; start a new interval. |
| `getDomainStats(): List<DomainStats>` | Cumulative stats since `init` / last `clearStats`, sorted by total bytes desc. |
| `getIntervalStats(): List<DomainStats>` | Last completed interval's stats, sorted by interval bytes desc. |
| `getTotalStats(): TotalStats` | Sum across all domains. The primary API for the "Java half" of total app traffic. |
| `setLogInterval(seconds: Int)` | Start / stop periodic `adb logcat` reports (tag `NetScope`). Pass `0` to stop. |
| `setOnFlowEnd(cb?)` | Register per-flow-close callback. Pass `null` to clear. |
| `destroy()` | Stop the reporter and clear state. Instrumentation stays in the bytecode; rebuild without the plugin to fully remove. |

### `DomainStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Target host |
| `txBytesTotal` / `rxBytesTotal` | `Long` | Cumulative bytes |
| `txBytesInterval` / `rxBytesInterval` | `Long` | Bytes in current / last interval window |
| `connCountTotal` / `connCountInterval` | `Int` | Closed-flow counts |
| `lastActiveMs` | `Long` | `System.currentTimeMillis()` of last activity |
| `totalBytes` | `Long` | Computed: `txBytesTotal + rxBytesTotal` |

### `TotalStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `txTotal` / `rxTotal` | `Long` | Sum across all domains |
| `connCountTotal` | `Int` | Sum across all domains |
| `totalBytes` | `Long` | Computed |

## Logcat Output Format

```
I NetScope: ══════ Traffic Report [2026-04-24 12:00:00] ══════
I NetScope: ── Interval ──────────────────────────────
I NetScope:   api.github.com                           ↑1.2 KB    ↓45.6 KB   conn=3
I NetScope:   www.google.com                           ↑0.8 KB    ↓12.1 KB   conn=1
I NetScope: ── Cumulative ────────────────────────────
I NetScope:   api.github.com                           ↑8.4 KB    ↓312.0 KB  conn=21
I NetScope:   www.google.com                           ↑3.2 KB    ↓88.7 KB   conn=7
I NetScope: ── Total (Java stack) ────────────────────
I NetScope:   ↑11.6 KB  ↓400.1 KB  conn=28
I NetScope: ═════════════════════════════════════════
```

## What gets instrumented

| Target method | Effect |
|---|---|
| `OkHttpClient.Builder.build()` | Prepended with `NetScopeInterceptorInjector.addIfMissing(this)` — idempotent, will not double-add if you've added the interceptor manually. |
| `URLConnection.getInputStream()` / `getOutputStream()` (including `HttpURLConnection` / `HttpsURLConnection`) | Return value wrapped in a counting `FilterInputStream` / `FilterOutputStream`. |
| `OkHttpClient.newWebSocket(Request, WebSocketListener)` | Listener wrapped to count inbound frames; returned `WebSocket` wrapped to count outbound `send(...)`. |

Classes in `okhttp3/`, `okio/`, `java/`, `javax/`, `android/`,
`androidx/`, `kotlin*/`, `com/android/`, `com/google/android/`,
`dalvik/` are skipped. AspectJ-synthesised classes (`$ajc$` / `$AjcClosure`)
are skipped. **Apply this plugin after AspectJ in your plugin order.**

## Known Limitations

- **Raw `OkHttpClient()` no-arg constructor** bypasses the Builder path
  and is therefore not instrumented. Prefer `OkHttpClient.Builder().build()`.
- **Reflection-constructed HTTP clients** are not instrumented —
  bytecode rewriting cannot see them.
- **Native HTTP clients** (NDK code, WebView / Chromium, libcurl via
  JNI) are out of scope. The integrator sums NetScope stats with the
  native stack's own reported numbers.
- **`java.net.Socket` direct use** is not instrumented. Open an issue
  if this blocks a concrete integration — the plugin has a
  straightforward extension path.
- **`pause()`** stops counting but does not stop bytes from flowing
  through wrappers. Re-building without the plugin is the only way to
  fully remove instrumentation.

## Contributors / maintainers

Human or AI agent picking up NetScope work should start at
[`docs/AGENT_HANDOFF.md`](docs/AGENT_HANDOFF.md) — a distilled,
action-oriented briefing covering the golden rules (AOP-G1 through
AOP-G9), the playbooks for common tasks, and the publish flow. If
someone proposes bringing the native hook backend back, first read
[`docs/BYTEHOOK_LESSONS.md`](docs/BYTEHOOK_LESSONS.md).

## Build from Source

```bash
git clone git@github.com:Arrowyi/NetScope.git
cd NetScope

# Build the SDK AAR (pure Kotlin, zero native libs):
./gradlew :netscope-sdk:assembleRelease
# → netscope-sdk/build/outputs/aar/netscope-sdk-release.aar

# Build the Gradle plugin (composite build):
./gradlew -p netscope-plugin jar
# → netscope-plugin/build/libs/netscope-plugin-<version>.jar

# Sample app (demonstrates the zero-touch integration):
./gradlew :app:assembleDebug
```

## License

```
Copyright 2025 Arrowyi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
