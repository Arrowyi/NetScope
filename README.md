# NetScope SDK

[![](https://jitpack.io/v/Arrowyi/NetScope.svg)](https://jitpack.io/#Arrowyi/NetScope)
[![API](https://img.shields.io/badge/API-29%2B-brightgreen.svg)](https://android-arsenal.com/api?level=29)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A lightweight Android SDK that monitors **all network traffic** in the embedding app — including Java and C++ (NDK) layers — without requiring a VPN or root access. Works on Android tablets and **Android Automotive OS (AAOS)** car systems where `VpnService` is unavailable.

## How It Works

NetScope uses **PLT Hook** (Procedure Linkage Table hooking) via [shadowhook](https://github.com/bytedance/android-inline-hook) to intercept network calls inside the app process. It attributes traffic to domain names via:

1. **TLS SNI** — parses the ClientHello plaintext to extract the server name
2. **HTTP Host header** — reads the `Host:` field from plaintext HTTP
3. **DNS cache** — hooks `getaddrinfo` to build an IP → domain map

Two independent hook targets cover all traffic without double-counting:

- **`libc.so`** — captures NDK C++ traffic and all non-TLS Java traffic (`connect`, `send`, `recv`, `getaddrinfo`, `close`, etc.)
- **`libconscrypt_jni.so`** — captures Java HTTPS traffic (OkHttp, `HttpsURLConnection`). Conscrypt routes TLS I/O through BoringSSL via JNI, bypassing the `libc.so` PLT; these hooks fill that gap.

```
        Java HTTPS                    NDK C++ / plaintext HTTP
    (OkHttp / HttpsURLConnection)
              │                                  │
              ▼                                  ▼
  PLT Hook (libconscrypt_jni.so)     PLT Hook (libc.so)
   send / recv / write / read         connect / send / recv / close
              │                                  │
              └──────────────┬───────────────────┘
                             ▼
               FlowTable (per-fd tracking)
               DnsCache  (IP → domain, 60 s TTL)
               StatsAggregator (atomic counters)
                             │
                             ▼
               NetScope Kotlin API
               (getDomainStats / LogcatReporter)
```

## Requirements

| Item | Requirement |
|------|-------------|
| Android API | 29+ (Android 10) |
| ABI | arm64-v8a, armeabi-v7a |
| NDK | r25c (25.2.9519653) |
| AGP | 8.2+ |
| Kotlin | 1.9+ |

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
    implementation 'com.github.Arrowyi:NetScope:v1.0.0'
}
```

Replace `v1.0.0` with the [latest release tag](https://github.com/Arrowyi/NetScope/releases).

**Step 3.** If you see a `libshadowhook.so` merge conflict, add to your app's `build.gradle`:

```groovy
android {
    packagingOptions {
        jniLibs {
            pickFirsts += ['**/libshadowhook.so']
        }
    }
}
```

### Option B — Local AAR

Download `netscope-sdk-release.aar` from [Releases](https://github.com/Arrowyi/NetScope/releases) and place it in your module's `libs/` folder:

```groovy
dependencies {
    implementation files('libs/netscope-sdk-release.aar')
    implementation 'com.bytedance.android:shadowhook:1.0.9'  // required transitive
    implementation 'androidx.annotation:annotation:1.7.1'
}
```

## Quick Start

### 1. Initialize in `Application.onCreate()`

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)

        // Print a traffic report to Logcat every 30 seconds (tag: NetScope)
        NetScope.setLogInterval(30)
    }
}
```

### 2. Query statistics anywhere

```kotlin
// Cumulative stats since init / last clearStats()
val stats: List<DomainStats> = NetScope.getDomainStats()
stats.forEach { s ->
    Log.i("Traffic", "${s.domain}  ↑${s.txBytesTotal}B  ↓${s.rxBytesTotal}B")
}

// Last completed interval (since last markIntervalBoundary())
val interval: List<DomainStats> = NetScope.getIntervalStats()
```

### 3. Flow-end callback

```kotlin
NetScope.setOnFlowEnd { stats ->
    // Called each time a TCP connection closes
    // stats.txBytesInterval / rxBytesInterval = bytes for that connection
    Log.d("NetScope", "Closed: ${stats.domain} ↑${stats.txBytesInterval}B ↓${stats.rxBytesInterval}B")
}
```

## API Reference

### `NetScope` (object)

| Method | Description |
|--------|-------------|
| `init(context)` | Install PLT hooks and start monitoring. Idempotent. |
| `pause()` | Suspend byte counting (hooks remain installed). |
| `resume()` | Resume byte counting after `pause()`. |
| `destroy()` | Uninstall all hooks and release resources. |
| `clearStats()` | Reset all counters. Hooks unaffected. |
| `markIntervalBoundary()` | Snapshot current-interval counters and start a new interval. |
| `getDomainStats(): List<DomainStats>` | Cumulative stats, sorted by total bytes desc. |
| `getIntervalStats(): List<DomainStats>` | Last completed interval stats, sorted by interval bytes desc. |
| `setLogInterval(seconds: Int)` | Start periodic Logcat report (tag `NetScope`). Pass `0` to stop. |
| `setOnFlowEnd(callback?)` | Register / unregister per-connection callback. Pass `null` to clear. |

### `DomainStats` (data class)

| Field | Type | Description |
|-------|------|-------------|
| `domain` | `String` | Domain name (or IP if resolution failed) |
| `txBytesTotal` | `Long` | Cumulative bytes sent |
| `rxBytesTotal` | `Long` | Cumulative bytes received |
| `txBytesInterval` | `Long` | Bytes sent in current/last interval |
| `rxBytesInterval` | `Long` | Bytes received in current/last interval |
| `connCountTotal` | `Int` | Total closed connections |
| `connCountInterval` | `Int` | Connections closed in current/last interval |
| `lastActiveMs` | `Long` | Timestamp of last activity (steady clock ms) |
| `totalBytes` | `Long` | Computed: `txBytesTotal + rxBytesTotal` |

## Logcat Output Format

```
I NetScope: ══════ Traffic Report [2025-04-21 12:00:00] ══════
I NetScope: ── Interval ──────────────────────────────
I NetScope:   api.github.com                           ↑1.2 KB    ↓45.6 KB   conn=3
I NetScope:   www.google.com                           ↑0.8 KB    ↓12.1 KB   conn=1
I NetScope: ── Cumulative ────────────────────────────
I NetScope:   api.github.com                           ↑8.4 KB    ↓312.0 KB  conn=21
I NetScope:   www.google.com                           ↑3.2 KB    ↓88.7 KB   conn=7
I NetScope: ═════════════════════════════════════════
```

## Known Limitations

- **Static-linked libc**: Extremely rare `.so` files that statically link libc cannot be hooked via PLT.
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
