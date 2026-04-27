# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight Android SDK that reports:

- **Layer A — Kernel-level total traffic for your UID since `init()`**
  via `android.net.TrafficStats`. Includes Java, Kotlin, C++, NDK,
  native libraries, raw sockets — anything the kernel counts for your
  app.
- **Layer B — Per-API (host + path) Java-layer breakdown** via
  build-time AOP instrumentation of `OkHttpClient.Builder.build()`,
  `HttpsURLConnection`, and `OkHttpClient.newWebSocket(...)`.
  API granularity (`api.example.com/v1/users/:id`) — numeric IDs,
  UUIDs, and long hex segments are templated so traffic for the same
  endpoint shape aggregates into one row.

Zero source-code changes to the host app. Works on phones, tablets,
and **Android Automotive** / OEM car head-units where `VpnService` /
root are unavailable.

## How It Works

NetScope uses **build-time AOP (ASM bytecode instrumentation)** via a
Gradle Transform plugin. When you apply `indi.arrowyi.netscope` to
your app module, every call to:

- `OkHttpClient.Builder.build()`
- `HttpsURLConnection.getInputStream()` / `getOutputStream()` (including
  `HttpURLConnection`, `URLConnection`)
- `OkHttpClient.newWebSocket(...)`

is rewritten at compile time to route through lightweight NetScope
wrappers that count bytes per-API (host + normalised path). For the
*total* number, NetScope additionally reads kernel-level `TrafficStats`
so native / non-instrumented traffic is not missing.

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
        Layer B: TrafficAggregator (AtomicLong counters, key = host + path)
                                             ▼
                                getApiStats / getIntervalStats

          Kernel (xt_qtaguid / eBPF)  ──►  TrafficStats.getUid{Tx,Rx}Bytes
                                             ▼
               Layer A: baseline captured at init(), subtracted on read
                                             ▼
                                getTotalStats
```

### Layer A vs Layer B — what each number means

`getTotalStats()` is "since `init()`, kernel-level, all sources".
`getApiStats()` is "since `init()`, AOP-observed Java HTTP/S, one
entry per (host, path)". The **gap** between them is non-instrumented
traffic — native HTTP clients, NDK / C++ code, libcurl, raw
`java.net.Socket`, signed binary blobs, plus anything emitted from a
class the Transform skips (see [What gets instrumented](#what-gets-instrumented)).
By construction:

```
sum(getApiStats().tx) <= getTotalStats().txTotal
```

HMIs that want to surface attribution can render the difference
explicitly:

```kotlin
val total      = NetScope.getTotalStats()
val attributed = NetScope.getApiStats().sumOf { it.txBytesTotal + it.rxBytesTotal }
val unattributed = total.totalBytes - attributed   // native + non-instrumented Java
```

### API key shape

Each `ApiStats` has two string fields and a derived `key = "$host$path"`:

| Field | Example |
|---|---|
| `host` | `api.example.com` (default-port scheme) |
|   | `api.example.com:8080` (non-default port surfaces automatically) |
|   | `192.168.1.5:9000` (raw IP + port for mystery internal services) |
|   | `<unknown>` or `<unknown>:9000` (unresolvable host; port preserved when known) |
| `path` | `/v1/users` (verbatim) |
|   | `/v1/users/:id` (numeric IDs templated) |
|   | `/accounts/:uuid/avatar` (UUIDs templated) |
|   | `/file/:hash` (long hex strings templated) |
|   | Query strings (`?q=...`) and fragments (`#...`) are stripped; trailing slashes dropped; `GET` and `POST` against the same path merge. |

Port handling drops the scheme default (HTTPS `:443` / HTTP `:80`) so
ordinary traffic stays clean, but a non-default port always shows up —
the same `api.example.com` on two different ports splits into two API
entries, which matches what the kernel / network actually treats them
as.

### Which URLs get counted

The Gradle Transform rewrites *every* `URLConnection.getInputStream()`
/ `getOutputStream()` call site in the app. At runtime NetScope
classifies the connection's URL before wrapping:

| URL | Counted? | Rationale |
|---|---|---|
| `http://…`, `https://…` | yes | obvious |
| `ftp://…`, `sftp://…`, custom socket schemes | yes | touches the wire |
| `jar:http://host/x.jar!/entry` | yes | inner URL is remote |
| `file:/data/…` | no | local filesystem |
| `content://…` | no | Android ContentProvider |
| `asset:`, `android.resource:`, `res:`, `data:` | no | local |
| `jar:file:/…!/entry` | no | inner URL is local |

The classifier uses a local-scheme **denylist** rather than an
http(s) **allowlist**. If a new over-the-wire transport appears
(say `quic:`), it will be counted by default — the denylist bias is
deliberately conservative about missing traffic and liberal about
counting it. Local-filesystem reads via `URLConnection` therefore
never leak into `getApiStats()` under an `<unknown>/…` row.

### Why this architecture

AOP + `TrafficStats` together give you "total traffic including
native" **without** shipping any native library. The Java layer is
visible per-API; the kernel layer fills in everything else (NDK,
WebView, raw sockets, prebuilt binaries). No `VpnService`, no root,
no native hook — works on locked-down OEM devices.

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
        classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v3.0.1'
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
    implementation 'com.github.Arrowyi.NetScope:NetScope:v3.0.1'
}
```

For a production build, pin to a tag from
[Releases](https://github.com/Arrowyi/NetScope/releases) or an exact
short SHA from
[github.com/Arrowyi/NetScope/commits/main](https://github.com/Arrowyi/NetScope/commits/main).
Avoid `main-SNAPSHOT` — JitPack re-resolves it on every fetch.

### Step 3 — Initialise in `Application.onCreate()`

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)                 // always returns ACTIVE
        NetScope.setLogInterval(30)         // optional periodic report
        NetScope.setOnFlowEnd { stats ->    // optional per-flow callback
            Log.d("NetScope", "${stats.key} ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
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
| `init(context): Status` | Idempotent. Clears per-API counters and captures a `TrafficStats` baseline so numbers are "since `init()`". Always returns `ACTIVE`. |
| `status(): Status` | Current state: `NOT_INITIALIZED` or `ACTIVE`. |
| `pause()` / `resume()` | Suspend / resume **per-API** counting. Affects Layer B only — `getTotalStats()` (Layer A / kernel) keeps counting. |
| `clearStats()` | Reset per-API counters AND re-capture kernel baseline, so both layers restart from 0. |
| `markIntervalBoundary()` | Freeze current-interval counters into the interval snapshot; start a new interval. |
| `getApiStats(): List<ApiStats>` | **Layer B.** AOP per-API (host + path) cumulative since `init()` / last `clearStats()`. Java-only. Sorted by total bytes desc. |
| `getIntervalStats(): List<ApiStats>` | Last completed interval's per-API stats. |
| `getTotalStats(): TotalStats` | **Layer A.** Kernel-level UID traffic (Java + native + NDK) since `init()`. Source: `TrafficStats.getUid{Tx,Rx}Bytes`. |
| `setLogInterval(seconds: Int)` | Start / stop periodic `adb logcat` reports (tag `NetScope`). Pass `0` to stop. |
| `setOnFlowEnd(cb?)` | Register per-flow-close callback. Pass `null` to clear. |
| `destroy()` | Stop the reporter and clear state. Instrumentation stays in the bytecode; rebuild without the plugin to fully remove. |

### `ApiStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `host` | `String` | Target host. May include `:port` when non-default for the scheme (`api.example.com:8080`, `192.168.1.5:9000`). Unresolvable hosts surface as `<unknown>` (or `<unknown>:port` when port is known). |
| `path` | `String` | Normalised URL path. Always starts with `/`; numeric IDs → `:id`, UUIDs → `:uuid`, long hex strings → `:hash`. Query and fragment stripped. |
| `key` | `String` | Derived: `"$host$path"`, e.g. `api.example.com/v1/users/:id`. Stable identifier. |
| `txBytesTotal` / `rxBytesTotal` | `Long` | Cumulative bytes |
| `txBytesInterval` / `rxBytesInterval` | `Long` | Bytes in current / last interval window |
| `connCountTotal` / `connCountInterval` | `Int` | Closed-flow counts |
| `lastActiveMs` | `Long` | `System.currentTimeMillis()` of last activity |
| `totalBytes` | `Long` | Computed: `txBytesTotal + rxBytesTotal` |

### `TotalStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `txTotal` / `rxTotal` | `Long` | Kernel-counted bytes for our UID since `init()` (covers Java + native + NDK). Falls back to AOP sum on pre-Q OEM kernels that return `TrafficStats.UNSUPPORTED`. |
| `connCountTotal` | `Int` | AOP-observed Java-layer flow-close count. Kernel has no "connection close" concept for native sockets, so this stays Java-only. |
| `totalBytes` | `Long` | Computed: `txTotal + rxTotal` |

## Logcat Output Format

```
I NetScope: ══════ Traffic Report [2026-04-24 12:00:00] ══════
I NetScope: ── Interval ──────────────────────────────
I NetScope:   api.github.com/repos/:id/issues                              ↑1.2 KB    ↓45.6 KB   conn=3
I NetScope:   www.google.com/complete/search                               ↑0.8 KB    ↓12.1 KB   conn=1
I NetScope:   192.168.1.5:9000/telemetry                                   ↑0.1 KB    ↓0.3 KB    conn=1
I NetScope: ── Cumulative ────────────────────────────
I NetScope:   api.github.com/repos/:id/issues                              ↑8.4 KB    ↓312.0 KB  conn=21
I NetScope:   api.github.com/user/:id                                      ↑1.1 KB    ↓4.2 KB    conn=3
I NetScope:   www.google.com/complete/search                               ↑3.2 KB    ↓88.7 KB   conn=7
I NetScope: ── Total (kernel UID, since init) ────────
I NetScope:   ↑18.3 KB  ↓512.0 KB  conn=28
I NetScope:   non-instrumented (native/NDK): 118.2 KB
I NetScope: ═════════════════════════════════════════
```

## What gets instrumented

| Target method | Effect |
|---|---|
| `OkHttpClient.Builder.build()` | Prepended with `NetScopeInterceptorInjector.addIfMissing(this)` — idempotent, will not double-add if you've added the interceptor manually. |
| `URLConnection.getInputStream()` / `getOutputStream()` (including `HttpURLConnection` / `HttpsURLConnection`) | Return value wrapped in a counting `FilterInputStream` / `FilterOutputStream`. |
| `OkHttpClient.newWebSocket(Request, WebSocketListener)` | Listener wrapped to count inbound frames; returned `WebSocket` wrapped to count outbound `send(...)`. |

### Classes the Transform skips (call-site rewrite only)

The Transform does not rewrite call sites that live inside the
following packages:

| Skipped prefix | Why it must be skipped |
|---|---|
| `okhttp3/`, `okio/` | OkHttp internally constructs `OkHttpClient` (redirect handlers, `Dispatcher`, etc.); rewriting these call sites would cause `NetScopeInterceptor` to be re-applied on top of itself. |
| `java/`, `javax/`, `android/`, `androidx/`, `com/android/`, `com/google/android/`, `dalvik/` | Boot classpath + Android framework + AndroidX + GMS. These classes are loaded from the platform / shared classloaders and any rewrites we ship are not actually used at runtime. |
| `kotlin/`, `kotlinx/` | Kotlin stdlib — same reason as above. |
| `$ajc$`, `$AjcClosure` | AspectJ-synthesised classes. Leaving them alone keeps AspectJ weaving correct. |
| `indi/arrowyi/netscope/...` | NetScope's own runtime, to prevent self-loops. |

> **This is a *call-site* skip, not a *traffic* skip.** Bytes that flow
> through these classes still count in `getTotalStats()` (kernel
> `TrafficStats`). They simply do not appear in `getApiStats()`'s
> per-API breakdown and surface as part of the `total - sum(apis)`
> gap.

#### Per-API blind spots this creates

`getApiStats()` is computed at the *caller* side of three OkHttp /
URLConnection methods. If the caller class lives under a skipped
prefix, that flow is invisible to the per-API breakdown. The
following are the realistic cases to be aware of:

| Source | Skipped prefix that hides it | What you lose from `getApiStats()` |
|---|---|---|
| Google Play Services / Firebase / FCM / Maps / Crashlytics / Auth | `com/google/android/` (`com.google.android.gms.*`, `com.google.android.libraries.*`) | All GMS-internal HTTP — token refresh, push long-poll, map tiles, crash uploads. |
| AndroidX Media3 / ExoPlayer streaming | `androidx/` (`androidx.media3.*`) | Streaming media DataSource traffic — usually the largest single contributor on car / video apps. |
| AndroidX WorkManager constraint pings, AndroidX Browser custom tabs | `androidx/` | Background HTTP for scheduled work, custom-tab prefetch. |
| Android framework HTTP (DownloadManager, sync adapters, some WebView fallbacks) | `android/`, `com/android/` | Java-side downloads / sync. WebView itself is mostly native and outside Layer B regardless. |
| Vendor / OEM AAR whose package is `com.android.*` or `com.google.android.*` | `com/android/`, `com/google/android/` | Whatever HTTP that AAR makes. Common on automotive / HMI projects integrating prebuilt AARs. |
| Business code accidentally obfuscated into `androidx.*` / `com.android.*` by ProGuard rules | matches the prefix | Same as a vendor AAR — looks like the plugin "stopped working" in release. |
| Network calls woven by AspectJ into `$AjcClosure` synthetic classes | `$AjcClosure` | The original call site moves into a synthetic class that NetScope leaves alone. |

In every case above the **traffic itself is still counted by
`getTotalStats()`** and surfaces inside the `total - sum(apis)`
difference. The HMI / dashboard label "non-instrumented (native/NDK)"
in the logcat sample is therefore a slight under-spec — that bucket
contains *both* genuine native traffic *and* Java traffic from the
skipped packages above. Treat it as "unattributed" rather than
"native".

#### Mitigations

- **Pin the plugin order.** Always apply `indi.arrowyi.netscope`
  *after* AspectJ. Reversing the order leaves AspectJ trying to weave
  over already-rewritten call sites and can fail at compile time.
- **Always render the gap.** UI / telemetry that surfaces per-API
  bytes should also surface `total - sum(apis)` as an "unattributed"
  row, not silently drop it.
- **Audit vendor AAR packages.** If integrating a prebuilt AAR whose
  package falls under `com/android/` or `com/google/android/`, expect
  it to be invisible to `getApiStats()`. If you need per-API
  visibility for it, repackage / consider lifting that prefix from
  the skip list (and re-test `Interceptor` chain compatibility — see
  next bullet).
- **Lifting a skip prefix is possible but risky.** For projects that
  must split GMS / ExoPlayer per-endpoint, the skip list in
  `NetScopeTransform.kt` can be relaxed for specific prefixes.
  Validate carefully: those libraries internally construct
  `OkHttpClient`s used as building blocks (e.g. ExoPlayer's
  `OkHttpDataSource.Factory`), and adding `NetScopeInterceptor` into
  every one of them may interact with their own interceptor chains.
  Roll out behind a build flag and verify on a real device.

## Known Limitations

- **Raw `OkHttpClient()` no-arg constructor** bypasses the Builder path
  and is therefore not visible in `getApiStats()`. Its traffic IS still
  counted in `getTotalStats()` (kernel-level). Prefer
  `OkHttpClient.Builder().build()` if you want the per-API breakdown.
- **Reflection-constructed HTTP clients** are not instrumented — per-
  API stats will miss them. `getTotalStats()` still includes their
  traffic.
- **Native HTTP clients** (NDK code, WebView / Chromium, libcurl via
  JNI) show up in `getTotalStats()` but not `getApiStats()`. Compute
  `total - sum(apis)` to surface this gap.
- **`java.net.Socket` direct use** is not per-API-instrumented but is
  counted in the kernel total.
- **Third-party libraries whose call sites live under skipped
  packages** (GMS, Firebase, AndroidX Media3 / ExoPlayer, vendor AARs
  shipped under `com.android.*` / `com.google.android.*`, AspectJ
  `$AjcClosure`-woven calls) are absent from `getApiStats()`. Their
  traffic is still counted in `getTotalStats()` and surfaces in the
  `total - sum(apis)` gap. See
  [Per-API blind spots this creates](#per-api-blind-spots-this-creates)
  for the full list and mitigations.
- **Path templating is heuristic.** `:id`/`:uuid`/`:hash` are applied
  per segment based on regex, so `/articles/some-natural-slug` stays
  literal (desired) but a numeric slug like `/articles/2026` collapses
  to `/articles/:id` (may be too aggressive for editorial APIs). A
  pluggable normaliser is on the roadmap if host apps need custom
  rules.
- **`pause()`** suspends Layer B (per-API) counting but does NOT
  suspend Layer A (kernel total). The kernel keeps counting regardless
  of SDK state.
- **Pre-Q OEM kernels** returning `TrafficStats.UNSUPPORTED` (-1) fall
  back to reporting the AOP sum in `getTotalStats()`. Rare on devices
  shipping API 26+.
- **Non-incremental Transform.** To allow vendor AAR call sites to be
  instrumented without tripping AGP 4.x's
  `mixed_scope_dex_archive` wide-scope duplicate-class collapse,
  NetScope's Transform reproduces AGP's scope-priority dedupe itself.
  That requires a fresh global seen-set each run, so the Transform
  opts out of incremental builds. Full rebuilds cost a few seconds
  more; the per-class bytecode prefilter keeps this minimal. Vendor
  AAR call sites ARE covered by `getApiStats()`.
- **Plugin order matters.** If AspectJ is also in the build, apply
  it **before** NetScope. NetScope skips `$ajc$` / `$AjcClosure`
  classes so AspectJ's weaving is preserved, but reversing the order
  can leave AspectJ trying to weave over already-rewritten call
  sites.

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
