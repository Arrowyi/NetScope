# NetScope AOP Integration Guide

This is the contract between NetScope and an integrating Android app.
It supersedes the previous native-hook integration docs. If you have a
`NETSCOPE_AOP_REQUEST.md` from the HMI-side team, the §10 build-stack
fact sheet you documented is reflected in the plugin's actual
constraints below.

---

## 1. What you need on the build stack

NetScope's plugin targets **AGP 4.2.2, Gradle 6.7.1, Kotlin 1.6.21, JDK 8**
as the minimum viable host. Other pairings (AGP 7.x, Gradle 7.x) have
been tested and work but are not the primary target.

| Concern | Requirement |
|---|---|
| AGP | 4.2.2+ (uses the legacy `com.android.build.api.transform.Transform` API; do NOT need AGP 7+ `AsmClassVisitorFactory`) |
| Gradle | 6.7.1+ |
| JDK running Gradle | 8+ (plugin jar is compiled to class major 52) |
| Kotlin | 1.6.21+ in the app module (the plugin uses no fancier Kotlin features) |
| AspectJ plugin order | If AspectJ is applied, the NetScope plugin must be applied **after** it |

If any of these cannot be met, file an issue before integrating.

---

## 2. Applying the plugin

Two things go into your build:

1. The **plugin** (Gradle classpath): does the build-time instrumentation.
2. The **runtime AAR**: contains the wrapper classes the instrumented
   bytecode calls into.

### 2.1 Project-level `build.gradle`

```groovy
buildscript {
    repositories {
        google()
        mavenCentral()
        maven { url 'https://jitpack.io' }   // already in Denali
    }
    dependencies {
        // Note: groupId is `com.github.Arrowyi.NetScope` (with a DOT, not a colon).
        // JitPack uses this multi-module convention because both artifacts ship
        // from the same repo.
        classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v2.0.3'
    }
}
```

### 2.2 App-module `build.gradle`

```groovy
apply plugin: 'com.android.application'
apply plugin: 'kotlin-android'

// Other plugins (AspectJ etc.) first, NetScope last.
// apply plugin: 'com.nfda.aspectj'
apply plugin: 'indi.arrowyi.netscope'

dependencies {
    implementation 'com.github.Arrowyi.NetScope:NetScope:v2.0.3'
    // OkHttp / HttpsURLConnection — already yours, NetScope uses
    // whatever version you have.
}
```

> **Pinning:** prefer a tag (`v2.0.3`) or an exact commit SHA. Avoid
> `main-SNAPSHOT` in production builds — JitPack rebuilds SNAPSHOTs on
> every fetch and will eventually version-skew.

### 2.3 Initialise once

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)
        NetScope.setLogInterval(30) // optional: adb logcat every 30 s
    }
}
```

That's it. No code changes on your OkHttp / URL connection / WebSocket
call sites. The plugin rewrites them at build time.

### 2.4 Two-layer data model (v2.0.2+)

**Layer A — Total traffic since init**: `getTotalStats()` reads
kernel-level UID counters via `android.net.TrafficStats`, and subtracts
a baseline snapshot captured at `init()`. Covers Java, Kotlin, C++,
NDK, native libraries, raw sockets — whatever the kernel attributes to
your UID. This is the "ground truth" number.

**Layer B — Per-domain breakdown**: `getDomainStats()` /
`getIntervalStats()` come from the AOP-instrumented Java call sites.
Java-only, per-host.

By construction the Layer-B sum is always ≤ the Layer-A total:

```
sum(getDomainStats().tx) <= getTotalStats().txTotal
```

The gap is non-instrumented traffic. If your app has a native HTTP
client, that traffic appears in Layer A but not Layer B. You can
surface the gap in your UI:

```kotlin
val total      = NetScope.getTotalStats()
val attributed = NetScope.getDomainStats().sumOf { it.txBytesTotal + it.rxBytesTotal }
val native     = (total.txTotal + total.rxTotal) - attributed
```

Effects of `init()` / `clearStats()` / `destroy()` on each layer:

| Call | Layer A (kernel total) | Layer B (per-domain) |
|---|---|---|
| `init()` (first) | Captures baseline → getTotalStats starts at 0 | Clears counters |
| `init()` (subsequent, already active) | No-op | No-op |
| `clearStats()` | Re-captures baseline → restarts at 0 | Clears counters |
| `destroy()` | Resets `initialized=false`; subsequent `init()` re-baselines | (Counters remain; instrumentation stays) |
| `pause()` / `resume()` | No effect (kernel keeps counting) | Suspends / resumes increments |

On pre-Q OEM kernels that return `TrafficStats.UNSUPPORTED` (-1),
`getTotalStats()` silently falls back to the AOP sum so the UI is not
blank.

---

## 3. What gets instrumented

| Target | Where | What the plugin emits |
|---|---|---|
| `okhttp3.OkHttpClient$Builder#build()` | every call site in PROJECT + SUB_PROJECTS + EXTERNAL_LIBRARIES (vendor AARs included) | `INVOKESTATIC NetScopeInterceptorInjector.addIfMissing(Builder)Builder` before the `build()` call |
| `java.net.URLConnection#getInputStream()` / `#getOutputStream()` (including `HttpURLConnection`, `HttpsURLConnection`) | every call site in PROJECT + SUB_PROJECTS + EXTERNAL_LIBRARIES | `INVOKESTATIC NetScopeUrlConnection.wrap{Input,Output}Stream(URLConnection, {In,Out}putStream){In,Out}putStream` wrapping the returned stream |
| `okhttp3.OkHttpClient#newWebSocket(Request, WebSocketListener)` | every call site in PROJECT + SUB_PROJECTS + EXTERNAL_LIBRARIES | wraps the `WebSocketListener` arg **and** the returned `WebSocket` for bidirectional counting |

> **v2.0.3 note on vendor AARs.** In HMI-style products it is common for
> heavy-network modules (search, map, voice, …) to be distributed as
> prebuilt AARs rather than as source sub-projects. v2.0.3's main
> scope therefore includes `EXTERNAL_LIBRARIES` — call sites inside
> these vendor AARs ARE rewritten and their traffic IS attributed to
> the right domain via `getDomainStats()`. See §3.1 below for the
> tiny build-side caveat this brings.

**What is NOT instrumented** (by design):

- Classes with `$ajc$` in the internal name or ending in `$AjcClosure`
  (AspectJ-synthesized) — leaving them alone so AspectJ's metadata
  stays coherent.
- Classes inside `okhttp3/`, `okio/`, `java/`, `javax/`, `android/`,
  `androidx/`, `kotlin*/`, `com/android/`, `com/google/android/`,
  `dalvik/` — to avoid infinite self-rewrites and keep the runtime
  contract narrow.
- NetScope's own packages.

### 3.1 Cross-scope duplicate-class dedupe (v2.0.3+)

Because the Transform's main scope now includes `EXTERNAL_LIBRARIES`,
on AGP 4.x AGP collapses every input into a single
`mixed_scope_dex_archive/` bucket and the downstream `DexMergingTask`
loses the per-scope dedupe it would normally apply. If two different
sources declare the same fully-qualified class name (typical example:
a local sub-project `:dr` AND a prebuilt `:dr` AAR whose manifest
carries the same `package="com.foo.dr"`, so AGP synthesises
`com.foo.dr.BuildConfig` in both), D8 would fail with
`Type ... is defined multiple times`.

NetScope's Transform handles this by reproducing AGP's per-scope
dedupe *inside itself*: inputs are processed in
`PROJECT > SUB_PROJECTS > EXTERNAL_LIBRARIES` order and a later
lower-priority input that re-declares an already-emitted class name
is silently dropped (with a log line at `--info` level). The
higher-priority copy wins — identical to what AGP would have done
without NetScope in the chain. Consumers do not need to configure
anything for this.

**Side-effect:** the Transform is non-incremental (dedupe needs a
fresh global seen-set every run). The per-class hot path is still
dominated by the bytecode prefilter introduced in v2.0.2, so the
additional cost on full builds is seconds, not minutes.

---

## 4. Proguard / R8 rules

Denali ships with R8 disabled (`android.enableR8=false`) and runs
Proguard. Add to your `proguard-sdk.txt` (or whatever chain you merge
into):

```proguard
# NetScope runtime — the instrumented bytecode references these by
# name; they MUST NOT be renamed, shrunk, or removed.
-keep class indi.arrowyi.netscope.sdk.** { *; }
-keep interface indi.arrowyi.netscope.sdk.integration.NetScopeInstrumented
-keepnames class indi.arrowyi.netscope.sdk.integration.NetScopeInterceptorInjector {
    public static okhttp3.OkHttpClient$Builder addIfMissing(okhttp3.OkHttpClient$Builder);
}
-keepnames class indi.arrowyi.netscope.sdk.integration.NetScopeUrlConnection {
    public static java.io.InputStream wrapInputStream(java.net.URLConnection, java.io.InputStream);
    public static java.io.OutputStream wrapOutputStream(java.net.URLConnection, java.io.OutputStream);
}
-keepnames class indi.arrowyi.netscope.sdk.integration.NetScopeWebSocket {
    public static java.lang.String hostOf(okhttp3.Request);
    public static okhttp3.WebSocketListener wrapListener(java.lang.String, okhttp3.WebSocketListener);
    public static okhttp3.WebSocket wrapWebSocket(java.lang.String, okhttp3.WebSocket);
}
```

The SDK AAR already carries a `consumer-rules.pro` with the
`-keep class indi.arrowyi.netscope.sdk.** { *; }` directive, which is
automatically consumed by R8 / Proguard. The rules above are safety
nets / explicit documentation for Proguard-only setups.

---

## 5. Reading stats

```kotlin
// Layer B — per domain, sorted by total bytes desc (Java HTTP/S only):
NetScope.getDomainStats().forEach { s ->
    Log.i("HMI", "${s.domain}  ↑${s.txBytesTotal}  ↓${s.rxBytesTotal}")
}

// Layer A — total traffic (includes Java + native + NDK):
val total = NetScope.getTotalStats()
Log.i("HMI", "TOTAL ↑${total.txTotal} ↓${total.rxTotal}")

// Per-interval (rolling):
NetScope.markIntervalBoundary()   // once per time tick
val interval = NetScope.getIntervalStats()
```

### Total traffic formula (v2.0.2+)

`getTotalStats()` is now self-contained — it reads
`android.net.TrafficStats.getUid{Tx,Rx}Bytes(myUid)` minus the baseline
captured at `init()`. No manual summing with native-stack stats is
needed:

```
getTotalStats()  =  all traffic the kernel counted for our UID since init()
                 =  Java HTTP/S (Layer B) + native / C++ / NDK / raw sockets
```

If you still want to show "how much traffic came from which source",
compute Layer-A minus the sum of Layer-B:

```kotlin
val native = total.totalBytes -
    NetScope.getDomainStats().sumOf { it.txBytesTotal + it.rxBytesTotal }
```

### Callbacks

```kotlin
NetScope.setOnFlowEnd { stats ->
    // Fires once per logical flow close
    // (HTTP response closed / URLConnection stream closed / WebSocket closed).
    // stats.txBytesInterval / rxBytesInterval = that flow's own bytes.
}
```

---

## 6. Verifying the instrumentation ran

```bash
# Any instrumented consumer class — pick one you know uses OkHttp:
javap -c -p app/build/intermediates/transforms/netscope/<variant>/<...>/MyApiClass.class \
    | grep -E 'NetScopeInterceptorInjector|NetScopeUrlConnection|NetScopeWebSocket'
```

You should see one `INVOKESTATIC` per instrumented call site. If the
output is empty, the Transform did not visit this class — check the
skip list in
[`NetScopeTransform.shouldSkipClass`](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt)
against the class's package.

At runtime, NetScope logs `[NetScope] registered Transform on application module :app` once per Gradle configure phase. The absence of this line in `./gradlew :app:assembleDebug --info` means the plugin was not applied to the right module.

---

## 7. Known integration edge cases

| Scenario | Behaviour |
|---|---|
| HMI adds `NetScopeInterceptor` manually AND the Transform runs | Injector sees the marker, skips injection. No double counting. |
| An OkHttp client is built inside a third-party AAR | Instrumented (Transform scope = FULL_PROJECT). |
| Library uses `OkHttpClient()` (no builder) | Not instrumented — OkHttp's no-arg constructor bypasses the Builder path. Acknowledged limitation; prefer `OkHttpClient.Builder().build()` everywhere. |
| App uses reflection to construct OkHttpClient | Not instrumented. Cannot be solved by a build-time Transform. |
| HTTPS via Chromium / WebView | Not in scope (native stack). |
| `java.net.Socket` direct use | Not instrumented. Add a new instrumenter if needed (see AGENT_HANDOFF §4.2). |
| AspectJ applied **after** NetScope | May produce `VerifyError` on classes AspectJ synthesises AFTER NetScope has already visited them. **Always apply AspectJ first, NetScope last.** |

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `java.lang.VerifyError` at class load | Class was mis-rewritten. Run `./gradlew :app:assembleDebug --info` and inspect the `[NetScope]` log line that mentions that class. File an issue with the class name; it will probably indicate a missing skip-list entry. |
| No traffic recorded, no errors | (a) Plugin not applied in the right module, (b) `NetScope.init()` not called, (c) The HTTP stack in use is not one we instrument (native? WebView?). |
| Traffic double-counted | Check for manual `.addInterceptor(NetScopeInterceptor)` mixed with Transform instrumentation; the marker should prevent this but `-keep` rules for `NetScopeInstrumented` are required in Proguard. |
| `UnsupportedClassVersionError` at plugin load | Gradle is running on JDK < 8, OR the plugin jar was accidentally built to major 55 (Java 11). Regenerate — the build.gradle pins jvmTarget to 1.8. |

For anything else, start at [AGENT_HANDOFF.md §4 Playbooks](AGENT_HANDOFF.md).
