# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An Android network-traffic monitoring SDK that exposes **four independent
diagnostic layers** — designed to cross-validate per-API attribution
against system-level totals and find hidden traffic consumers.

| Layer | Name | Data source | Granularity | Module |
|-------|------|-------------|-------------|--------|
| **A** | Kernel total | `TrafficStats.getUid{Tx,Rx}Bytes` | UID total | `netscope-sdk` |
| **B** | Java AOP | Build-time ASM bytecode transform | `host + path` | `netscope-sdk` |
| **C** | C++ HTTP client | `tn::http::client` callback → JNI | `host + path` | `netscope-sdk` |
| **D** | Socket hook | Self-written PLT / GOT hook | `IP:port` | `netscope-hook` *(optional)* |

Zero source-code changes to the host app. Works on phones, tablets, and
**Android Automotive / OEM car head-units** where `VpnService` / root are
unavailable.

---

## How It Works

### Layer B — Java AOP (build-time)

The `indi.arrowyi.netscope` Gradle plugin applies an ASM bytecode
Transform at compile time. Every call to:

- `OkHttpClient.Builder.build()`
- `HttpsURLConnection.getInputStream()` / `getOutputStream()` (including `HttpURLConnection`, `URLConnection`)
- `OkHttpClient.newWebSocket(...)`

is rewritten to route through lightweight NetScope wrappers that count
bytes per `(host, normalised-path)` pair.

### Layer A — Kernel total (runtime)

At `init()` NetScope captures a `TrafficStats` baseline and subtracts it
on every `getTotalStats()` call. This covers **all** traffic your UID
produces — Java, Kotlin, C++, NDK, raw sockets, prebuilt `.so` files.
It is the ground-truth against which the other layers are validated.

### Layer C — C++ HTTP client (runtime, opt-in integration)

The HMI's native build drops in two reference files
(`netscope_cpp_bridge.h/cpp`) and calls `netscope_install_cpp_hook()` once
during native initialisation. The bridge injects a global
`tn::http::client::injectGlobalOption()` callback that forwards each
completed request to `NetScope.reportCppFlow()` via JNI.

### Layer D — Socket hook (runtime, optional module)

`libnetscope_hook.so` (shipped in the separate `netscope-hook` module)
patches the GOT entries of `connect`, `send`, `sendto`, `sendmsg`,
`recv`, `recvfrom`, `recvmsg`, `write`, `read`, and `close` in every
loaded `.so` at runtime. On each `close()` the accumulated tx/rx for
that fd is flushed into a per-`IP:port` aggregation table.

The patcher uses only `dl_iterate_phdr` + `mprotect` on existing pages —
no `mmap(PROT_EXEC)`, no third-party hook libraries, W^X-kernel-safe.

Because `libcurl` (used internally by `tn::http::client`) calls the same
libc socket functions, Layer D captures C++ HTTP traffic at the wire level,
including TLS handshake bytes that Layer C does not count. DNS queries via
`c-ares` (UDP `sendto` / `recvfrom`) are hooked too.

```
  Java OkHttp / URLConnection / WebSocket
          │
          ▼
  ┌───────────────────────────────────────────────┐
  │  NetScope Gradle Transform  (build time)       │  ← Layer B
  │  .build()   → + NetScopeInterceptor            │
  │  .getInputStream() → + counting stream         │
  │  .newWebSocket() → wrapped listener/WebSocket  │
  └───────────────────────┬───────────────────────┘
                          ▼
              TrafficAggregator   getApiStats()

  tn::http::client callback (C++ side, via JNI)
          │
          ▼
  NetScope.reportCppFlow(url, tx, rx, ms)          ← Layer C
          ▼
      CppTrafficAggregator   getCppApiStats()

  connect / send / recv / close  (all .so files)
          │
          ▼
  libnetscope_hook.so  GOT patcher                 ← Layer D (optional)
          ▼
      fd_table aggregation   NetScopeHook.getSocketStats()

  Kernel  xt_qtaguid / eBPF
          │
          ▼
  TrafficStats.getUid{Tx,Rx}Bytes                  ← Layer A
          ▼
      NetScope.getTotalStats()
```

---

## 4-Layer Cross-Validation

The four layers are **independent views of the same traffic, not additive
buckets**. A single HTTPS request may appear in Layer B *and* Layer C
*and* Layer D simultaneously. The purpose is cross-validation, not
summation.

```
Layer A  ≈  sum(Layer D)
    // D covers all TCP sockets; gap ≈ UDP/DNS and sockets closed
    // before hooks were installed

Layer B + Layer C  ≈  Layer A
    // if B+C < A: traffic exists outside Java HTTP and tn::http::client

Layer A − Layer B − Layer C  =  unattributed gap
    // NDK, WebView, asdk.httpclient, raw sockets, prebuilt binaries
```

**Do NOT sum B + C + D and compare to A** — you will triple-count every
request that appears in all three.

---

## Requirements

| Item | Requirement |
|------|-------------|
| Android API | 29+ (Android 10) |
| AGP | **4.2.2+** (legacy `Transform` API; AGP 7.x / 8.x also work) |
| Gradle | 6.7.1+ |
| JDK running Gradle | 8+ |
| Kotlin | 1.6.21+ |
| NDK *(Layer D only)* | r25c (25.2.9519653 recommended) |

---

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
        // groupId uses a DOT, not a colon — JitPack multi-module convention.
        classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v3.1.0'
    }
}
```

### Step 2 — Apply the plugin and add runtime dependencies

App-module `build.gradle`:

```groovy
apply plugin: 'com.android.application'
apply plugin: 'kotlin-android'
// If you use AspectJ, apply it BEFORE NetScope (plugin order matters).
apply plugin: 'indi.arrowyi.netscope'

dependencies {
    // Layer A + B + C runtime
    implementation 'com.github.Arrowyi.NetScope:NetScope:v3.1.0'

    // Layer D socket hook — optional; remove if not needed
    implementation 'com.github.Arrowyi.NetScope:NetScopeHook:v3.1.0'
}
```

### Step 3 — Initialise in `Application.onCreate()`

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        // Layers A + B are active immediately after init().
        NetScope.init(this)
        NetScope.setLogInterval(30)          // optional periodic logcat report
        NetScope.setOnFlowEnd { stats ->     // optional per-flow callback (Layer B)
            Log.d("NetScope", "${stats.key} ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
        }

        // Layer D — optional socket hook
        NetScopeHook.init(this)   // loads libnetscope_hook.so; silent on failure
        NetScopeHook.start()      // installs GOT hooks; returns false if unavailable
    }
}
```

No changes anywhere else in your app — OkHttp clients, URL connections,
and WebSockets are instrumented at build time.

### Step 4 — Layer C: C++ HTTP client integration *(optional)*

#### How the integration works (decoupled design)

NetScope does **not** link against `tn::http::client` or any HMI native
library. The bridge is a thin adapter that the HMI team drops into their
own native build. It depends only on:

- `<foundation/http/client.hpp>` — already on the HMI include path
- `<jni.h>` — standard NDK header
- The SDK JAR on the Java classpath (for `NetScope.reportCppFlow()`)

Neither `libnetscope.so` nor `libnetscope_hook.so` appears in the
bridge's `DT_NEEDED`.

#### `tn::http::client` callback API

The integration point is the global option injector declared in
`<foundation/http/client.hpp>`:

**tasdk-android-unified** (public namespace function — callable directly):
```cpp
// namespace tn::http::client::restricted
TASDK_FOUNDATION_API void injectGlobalOption(OptionSetter opt);
```

**navcore** (private static in a friend class — only `InternalEvtMgr` has access):
```cpp
class restricted {
    friend class tn::datasense::InternalEvtMgr;
    static void injectGlobalOption(OptionSetter opt);  // NOT callable from HMI code
};
```

> **navcore limitation:** `injectGlobalOption` is `private` in navcore.
> The reference bridge files work with tasdk-android-unified but not with
> a navcore build as-is. In that case use the tasdk headers, or request
> that the navcore team expose the method.

The `ResponseListener` callback signature is identical in both SDKs:
```cpp
using ResponseListener = std::function<void(const Response&)>;
// On completion, res provides:
//   res.request().url()       — full request URL
//   res.bytesSent()           — bytes sent (size_t)
//   res.bytesReceived()       — bytes received (size_t)
//   res.totalTransferTime()   — wall-clock seconds (double)
```

#### Installation

Copy `docs/cpp-bridge/netscope_cpp_bridge.{h,cpp}` into your HMI native
source tree (e.g. alongside `DataUsageCollector.cpp`) and call
`netscope_install_cpp_hook()` once during native initialisation:

```cpp
// In JNI_OnLoad or next to DataUsageCollector::install():
#include "netscope_cpp_bridge.h"

netscope_install_cpp_hook(env, nullptr);   // idempotent, thread-safe
```

The two global options (DataUsageCollector's and NetScope's) coexist —
`injectGlobalOption` chains them, it does not replace one with the other.

No Kotlin-side changes are needed — stats accumulate into
`NetScope.getCppApiStats()` automatically.

---

## Querying the Four Layers

### Per-API breakdown

```kotlin
// Layer A — kernel ground truth (UID total, no per-API)
val total: TotalStats = NetScope.getTotalStats()

// Layer B — Java AOP, per (host + path)
val apiStats: List<ApiStats> = NetScope.getApiStats()       // cumulative
val interval: List<ApiStats> = NetScope.getIntervalStats()  // last interval

apiStats.forEach { s ->
    Log.d("NetScope", "[B] ${s.key}  ↑${s.txBytesTotal}  ↓${s.rxBytesTotal}  flows=${s.connCountTotal}")
}
// s.key == "api.example.com/v1/users/:id"

// Layer C — C++ HTTP client (tn::http::client), per (host + path)
val cppStats: List<CppApiStats> = NetScope.getCppApiStats()

cppStats.forEach { s ->
    Log.d("NetScope", "[C] ${s.key}  ↑${s.txBytes}  ↓${s.rxBytes}  req=${s.requestCount}  avg=${"%.1f".format(s.avgTransferTimeMs)}ms")
}
// s.key uses the same "host/path" shape as Layer B — rows can be compared directly

// Layer D — socket hook, per remote IP:port (not host+path — socket level has no hostname)
val sockets:   List<SocketStats>  = NetScopeHook.getSocketStats()
val sockTotal: SocketTotalStats   = NetScopeHook.getSocketTotalStats()

sockets.forEach { s ->
    Log.d("NetScope", "[D] ${s.remoteAddress}  ↑${s.txBytes}  ↓${s.rxBytes}  conn=${s.connectionCount}")
}
// s.remoteAddress == "203.0.113.1:443"
```

### Cross-validation

```kotlin
val bTx = apiStats.sumOf { it.txBytesTotal }
val cTx = cppStats.sumOf { it.txBytes }
val dTx = sockTotal.txTotal
val unattributed = total.txTotal - bTx - cTx   // traffic outside Java + tn::http
Log.d("NetScope",
    "A=${total.txTotal}  B=$bTx  C=$cTx  D=$dTx  gap=$unattributed")
```

---

## API Reference

### `NetScope` (object, in `netscope-sdk`)

| Method | Description |
|--------|-------------|
| `init(context): Status` | Idempotent. Captures a `TrafficStats` baseline; clears per-API counters. Always returns `ACTIVE`. |
| `status(): Status` | `NOT_INITIALIZED` or `ACTIVE`. |
| `pause()` / `resume()` | Suspend / resume Layer B counting only. Layer A kernel total keeps running. |
| `clearStats()` | Reset Layer B + C counters and re-capture kernel baseline. |
| `markIntervalBoundary()` | Freeze current-interval snapshot; start a new interval. |
| `getApiStats(): List<ApiStats>` | **Layer B.** AOP per-`(host, path)`, cumulative. Sorted by total bytes desc. |
| `getIntervalStats(): List<ApiStats>` | **Layer B.** Last completed interval's per-API stats. |
| `getTotalStats(): TotalStats` | **Layer A.** Kernel UID bytes since `init()`. Source: `TrafficStats.getUid{Tx,Rx}Bytes`. |
| `getCppApiStats(): List<CppApiStats>` | **Layer C.** C++ HTTP client per-`(host, path)`, cumulative since `init()` / last `clearCppApiStats()`. |
| `clearCppApiStats()` | Reset Layer C counters only. |
| `reportCppFlow(rawUrl, txBytes, rxBytes, durationMs)` | JNI entry point called by the C++ bridge — not called from Kotlin directly. `@JvmStatic`. |
| `setLogInterval(seconds: Int)` | Start / stop periodic logcat report (tag `NetScope`). Pass `0` to stop. |
| `setOnFlowEnd(cb?)` | Per-flow-close callback for Layer B. Pass `null` to clear. |
| `destroy()` | Stop reporter, clear state. Bytecode instrumentation remains; rebuild without the plugin to remove it. |

### `ApiStats` (data class, Layer B)

| Field | Type | Description |
|-------|------|-------------|
| `host` | `String` | Formatted endpoint. Default port for scheme is elided (`api.example.com`); non-default port appended (`api.example.com:8080`); raw IPs pass through (`192.168.1.5:9000`); unresolvable → `<unknown>`. |
| `path` | `String` | Normalised path. Always starts with `/`. Numeric IDs → `:id`, UUIDs → `:uuid`, long hex → `:hash`. Query/fragment stripped. |
| `key` | `String` | `"$host$path"` — stable identifier, e.g. `api.example.com/v1/users/:id`. |
| `txBytesTotal` / `rxBytesTotal` | `Long` | Cumulative bytes sent / received. |
| `txBytesInterval` / `rxBytesInterval` | `Long` | Bytes in the current / last interval window. |
| `connCountTotal` / `connCountInterval` | `Int` | Closed-flow counts. |
| `lastActiveMs` | `Long` | `System.currentTimeMillis()` of last activity. |
| `totalBytes` | `Long` | `txBytesTotal + rxBytesTotal`. |

### `TotalStats` (data class, Layer A)

| Field | Type | Description |
|-------|------|-------------|
| `txTotal` / `rxTotal` | `Long` | Kernel-counted bytes for the app's UID since `init()`. Falls back to AOP sum on pre-Q kernels returning `TrafficStats.UNSUPPORTED`. |
| `connCountTotal` | `Int` | AOP-observed Java-layer flow-close count (kernel has no per-connection close event). |
| `totalBytes` | `Long` | `txTotal + rxTotal`. |

### `CppApiStats` (data class, Layer C)

| Field | Type | Description |
|-------|------|-------------|
| `host` | `String` | Same formatting rules as `ApiStats.host`. |
| `path` | `String` | Same normalisation rules as `ApiStats.path`. |
| `key` | `String` | `"$host$path"`. |
| `txBytes` / `rxBytes` | `Long` | Cumulative bytes since `init()` / last `clearCppApiStats()`. |
| `requestCount` | `Int` | Number of completed C++ HTTP requests reported. |
| `totalTransferTimeMs` | `Double` | Sum of per-request transfer times (ms). |
| `totalBytes` | `Long` | `txBytes + rxBytes`. |
| `avgTransferTimeMs` | `Double` | `totalTransferTimeMs / requestCount` (0 if no requests). |

### `SocketStats` (data class, Layer D)

| Field | Type | Description |
|-------|------|-------------|
| `remoteAddress` | `String` | `"203.0.113.1:443"` — IP and port as seen by `connect()`. |
| `txBytes` / `rxBytes` | `Long` | Cumulative bytes since last `clearSocketStats()`. |
| `connectionCount` | `Int` | Number of `close()` events on fds connected to this address. |
| `totalBytes` | `Long` | `txBytes + rxBytes`. |

### `SocketTotalStats` (data class, Layer D)

| Field | Type | Description |
|-------|------|-------------|
| `txTotal` / `rxTotal` | `Long` | Sum across all `SocketStats` entries. |
| `connectionCount` | `Int` | Total closed connections across all remote addresses. |
| `totalBytes` | `Long` | `txTotal + rxTotal`. |

### `NetScopeHook` (object, in `netscope-hook`)

| Method / Property | Description |
|-------------------|-------------|
| `init(context)` | Loads `libnetscope_hook.so` via `System.loadLibrary`. Silent on failure (unsupported ABI, W^X kernel, etc.). Must be called before `start()`. |
| `start(): Boolean` | Installs GOT hooks on all currently-loaded `.so` files. Returns `false` if `init()` failed or the patcher encountered an error. |
| `stop()` | Uninstalls GOT hooks, restoring original function pointers. |
| `isActive: Boolean` | Whether hooks are currently installed. |
| `getSocketStats(): List<SocketStats>` | **Layer D.** Per-`IP:port` snapshot. Only connections that have been `close()`d appear; in-flight fds are not yet reported. Sorted by total bytes desc. |
| `getSocketTotalStats(): SocketTotalStats` | **Layer D.** Sum across all tracked addresses. Compare `txTotal` to `NetScope.getTotalStats().txTotal` for cross-validation. |
| `clearSocketStats()` | Reset Layer D counters. Hooks remain active; new stats accumulate from this point. |

---

## API key shape

Both `ApiStats` (Layer B) and `CppApiStats` (Layer C) use the same
`host + path` key shape, so you can compare them row-by-row:

| Field | Example |
|-------|---------|
| `host` | `api.example.com` — default port elided |
| | `api.example.com:8080` — non-default port shown |
| | `192.168.1.5:9000` — raw IP |
| | `<unknown>` — unresolvable host |
| `path` | `/v1/users` — verbatim |
| | `/v1/users/:id` — numeric segment templated |
| | `/accounts/:uuid/avatar` — UUID templated |
| | `/file/:hash` — long hex templated |
| | Query (`?q=…`) and fragment (`#…`) stripped; trailing slash dropped |

---

## Which URLs get counted (Layer B)

The Transform rewrites every `URLConnection.getInputStream()` /
`getOutputStream()` call site. At runtime NetScope classifies by scheme:

| URL | Counted? | Reason |
|-----|----------|--------|
| `http://…`, `https://…` | yes | network |
| `ftp://…`, `sftp://…`, custom socket schemes | yes | touches the wire |
| `jar:http://host/x.jar!/entry` | yes | inner URL is remote |
| `file:/data/…` | **no** | local filesystem |
| `content://…` | **no** | Android ContentProvider |
| `asset:`, `android.resource:`, `res:`, `data:` | **no** | local |
| `jar:file:/…!/entry` | **no** | inner URL is local |

The classifier uses a **denylist** (not an allowlist). A new
over-the-wire transport like `quic:` is counted by default.

---

## Logcat Output

```
I NetScope: ══════ Traffic Report [2026-05-04 12:00:00] ══════
I NetScope: ── Layer B: Interval (Java AOP) ───────────────
I NetScope:   api.example.com/v1/location           ↑1.2 KB  ↓45.6 KB  conn=3
I NetScope:   api.example.com/v1/map-tiles          ↑0.8 KB  ↓12.1 KB  conn=1
I NetScope: ── Layer B: Cumulative ──────────────────────
I NetScope:   api.example.com/v1/location           ↑8.4 KB  ↓312.0 KB conn=21
I NetScope: ── Layer C: C++ HTTP (cumulative) ───────────
I NetScope:   api.example.com/v1/location           ↑7.9 KB  ↓308.1 KB req=20
I NetScope: ── Layer A: Total (kernel UID, since init) ──
I NetScope:   ↑18.3 KB  ↓512.0 KB
I NetScope:   unattributed (A − B − C): 3.0 KB
I NetScope: ═════════════════════════════════════════════
```

---

## What gets instrumented (Layer B)

| Target | Effect |
|--------|--------|
| `OkHttpClient.Builder.build()` | Inserts `NetScopeInterceptorInjector.addIfMissing(this)` — idempotent. |
| `URLConnection.getInputStream()` / `getOutputStream()` | Return value wrapped in a counting `FilterInputStream` / `FilterOutputStream`. |
| `OkHttpClient.newWebSocket(Request, WebSocketListener)` | Listener and returned `WebSocket` both wrapped. |

### Classes the Transform skips

| Skipped prefix | Reason |
|----------------|--------|
| `okhttp3/`, `okio/` | OkHttp internally creates `OkHttpClient` instances; re-wrapping causes self-loops. |
| `java/`, `javax/`, `android/`, `androidx/`, `com/android/`, `com/google/android/`, `dalvik/` | Platform / framework / AndroidX / GMS — loaded from shared classloaders; rewrites are never used at runtime. |
| `kotlin/`, `kotlinx/` | Kotlin stdlib — same reason. |
| `$ajc$`, `$AjcClosure` | AspectJ synthetic classes — skip preserves AspectJ weaving. |
| `indi/arrowyi/netscope/` | NetScope's own runtime — prevents self-loops. |

> **Call-site skip ≠ traffic skip.** Traffic from skipped packages still
> appears in `getTotalStats()` (Layer A) and in `getSocketStats()` (Layer D).
> It is absent only from `getApiStats()` (Layer B).

### Realistic Layer B blind spots

| Source | Missing from `getApiStats()` |
|--------|------------------------------|
| GMS / Firebase / FCM / Maps | All GMS-internal HTTP |
| AndroidX Media3 / ExoPlayer | Streaming media traffic |
| AndroidX WorkManager / Browser | Background HTTP, custom-tab prefetch |
| `DownloadManager`, sync adapters | Java-side Android framework downloads |
| Vendor AARs under `com.android.*` / `com.google.android.*` | All HTTP from those AARs |
| AspectJ `$AjcClosure`-woven calls | The woven call site is in a synthetic class |

In all cases the traffic is visible in Layer A (`getTotalStats()`) and,
if the socket hook is enabled, in Layer D (`getSocketStats()`).

---

## No double counting within Layer B

Every NetScope wrapper implements the `NetScopeInstrumented` marker
interface. Both the Transform and the runtime injectors check for it
before wrapping:

- Transform + manual `addInterceptor(NetScopeInterceptor)` = **1× count**
- A `URLConnection` already wrapped won't be double-wrapped by a nested call site
- OkHttp on top of a wrapped `URLConnection` — only the top-most wrapper counts

Layers B, C, and D are independent — the same request appears in each.
Never sum them.

---

## Known Limitations

- **Layer C on navcore builds:** `tn::http::client::restricted::injectGlobalOption`
  is a `private static` method in navcore (accessible only via `InternalEvtMgr`).
  The reference bridge in `docs/cpp-bridge/` works with **tasdk-android-unified**
  only. For navcore, request access or use Layer D (socket hook) as a substitute.
- **`OkHttpClient()` no-arg constructor** bypasses the Builder and is
  invisible to Layer B. Traffic still counted in Layer A and D.
- **Reflection-constructed HTTP clients** are not instrumented in Layer B.
- **Native HTTP clients** (NDK, WebView/Chromium, libcurl via JNI) are not
  in Layer B. They appear in Layer A; with Layer D enabled they appear in
  `getSocketStats()` as `IP:port` entries.
- **`java.net.Socket` direct use** — not in Layer B; visible in Layer A and D.
- **GMS / AndroidX / vendor AARs under skipped packages** — not in Layer B;
  in Layer A and D. See [Realistic Layer B blind spots](#realistic-layer-b-blind-spots).
- **Path templating is heuristic.** `/articles/2026` → `/articles/:id`; a
  natural slug like `/articles/hello-world` stays literal. Custom rules via a
  pluggable `PathNormalizer` are on the roadmap.
- **`pause()`** suspends Layer B only. Layer A kernel total keeps counting.
- **Layer D counts only closed connections.** In-flight fds are not yet
  reported. Long-lived connections (keep-alive, streaming) may appear late.
- **Layer D covers TCP sockets.** UDP (DNS, QUIC) is not tracked by the
  `connect` / `send` / `recv` path in libc.
- **Pre-Q OEM kernels** returning `TrafficStats.UNSUPPORTED` fall back to
  the AOP sum in `getTotalStats()`.
- **Non-incremental Transform.** Scope-priority dedupe requires a fresh
  global seen-set each build run; incremental builds are disabled. Full
  rebuilds cost a few extra seconds; the per-class prefilter keeps this low.
- **Plugin order matters.** Apply AspectJ **before** `indi.arrowyi.netscope`.

---

## Build from Source

```bash
git clone git@github.com:Arrowyi/NetScope.git
cd NetScope

# SDK AAR (pure Kotlin, zero native libs)
./gradlew :netscope-sdk:assembleRelease
# → netscope-sdk/build/outputs/aar/netscope-sdk-release.aar

# Hook module AAR (requires NDK r25c)
./gradlew :netscope-hook:assembleRelease
# → netscope-hook/build/outputs/aar/netscope-hook-release.aar

# Gradle plugin (composite build)
./gradlew -p netscope-plugin jar
# → netscope-plugin/build/libs/netscope-plugin-<version>.jar

# Unit tests
./gradlew :netscope-sdk:test

# Sample app
./gradlew :app:assembleDebug
```

---

## License

```
Copyright 2025 Arrowyi

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```
