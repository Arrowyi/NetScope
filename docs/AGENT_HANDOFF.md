# NetScope — Agent Handoff

> Read this first if you are picking up NetScope maintenance — whether
> as a human engineer or an AI coding assistant. It is a distilled,
> action-oriented briefing for the current (post-2026-04-24) design:
> **pure Kotlin/Java AOP runtime + a Gradle Transform plugin**.
>
> The prior native/bytehook era is retired. See
> [BYTEHOOK_LESSONS.md](BYTEHOOK_LESSONS.md) for the postmortem and
> [HOOK_EVOLUTION.md](HOOK_EVOLUTION.md) for the historical chronicle.

---

## 1. What NetScope is, now

NetScope is an Android SDK that collects **per-domain Java-layer
network traffic statistics** for the embedding app by instrumenting
OkHttp, HttpsURLConnection, and OkHttp WebSocket at **build time** via
a Gradle Transform plugin. It observes only Java-layer traffic; native
HTTP clients (e.g. Telenav `asdk.httpclient`) are counted by their
own stacks.

```
total_app_traffic  =  NetScope.getTotalStats()  +  <native stack's own stats>
```

The SDK is pure Kotlin. There is no `libnetscope.so`, no bytehook, no
shadowhook. `DT_NEEDED` is empty of third-party libs. There is no
runtime failure path left for hook installation, because there is no
hook installation — everything is decided at build time, in the
Transform.

---

## 2. Repository map

```
NetScope/
├── netscope-sdk/                 ← AAR. Pure Kotlin, zero .so.
│   └── src/main/kotlin/indi/arrowyi/netscope/sdk/
│       ├── NetScope.kt           ← public entry point
│       ├── Status.kt             ← { NOT_INITIALIZED, ACTIVE }
│       ├── DomainStats.kt        ← per-domain row (data class)
│       ├── TotalStats.kt         ← sum across all domains
│       ├── LogcatReporter.kt     ← optional periodic adb logcat
│       ├── internal/
│       │   └── TrafficAggregator.kt   ← per-domain AtomicLong counters
│       └── integration/
│           ├── NetScopeInstrumented.kt  ← marker interface (anti-double-wrap)
│           ├── NetScopeInterceptor.kt   ← OkHttp Interceptor + injector
│           ├── NetScopeUrlConnection.kt ← HttpsURLConnection stream wrappers
│           └── NetScopeWebSocket.kt     ← OkHttp WebSocket wrapping
├── netscope-plugin/              ← Gradle Transform. Composite-build.
│   └── src/main/kotlin/indi/arrowyi/netscope/plugin/
│       ├── NetScopePlugin.kt     ← entry point, registers Transform
│       ├── NetScopeTransform.kt  ← com.android.build.api.transform.Transform
│       └── instrumenter/
│           ├── OkHttpBuilderInstrumenter.kt   ← rewrites .build()
│           ├── UrlConnectionInstrumenter.kt   ← wraps getInput/OutputStream
│           └── OkHttpWebSocketInstrumenter.kt ← wraps newWebSocket
├── app/                          ← Sample. Zero-touch integration demo.
└── docs/
    ├── AGENT_HANDOFF.md          ← you are here
    ├── AOP_INTEGRATION.md        ← HMI-facing integration guide
    ├── BYTEHOOK_LESSONS.md       ← native-era postmortem
    └── HOOK_EVOLUTION.md         ← historical chronicle (retired)
```

---

## 3. Golden rules (AOP era)

These are the invariants the design assumes. Violating one re-opens a
class of bug we've already closed.

| # | Rule | Rationale |
|---|---|---|
| AOP-G1 | Every wrapper object (interceptor, request body, source, sink, listener, websocket) implements `NetScopeInstrumented`. | This is the only mechanism guaranteeing "no double-count" when both the Transform AND a manually wired integration fire. |
| AOP-G2 | Runtime integration helpers (`NetScopeInterceptorInjector.addIfMissing`, `NetScopeUrlConnection.wrapInputStream`, `NetScopeWebSocket.wrapListener` / `wrapWebSocket`) must always check the marker before wrapping. | See AOP-G1. |
| AOP-G3 | Never re-introduce a native hook backend without first answering §7 of `BYTEHOOK_LESSONS.md`. | Two independent device models proved the static footprint alone is a destabiliser. |
| AOP-G4 | The NetScope Transform is applied **AFTER** AspectJ in the consumer's plugin order. Any class with `$ajc$` in its internal name or ending in `$AjcClosure` is skipped. | HMI runs AspectJ 1.9.4; mis-visiting its synthetic classes produces VerifyError at class load. |
| AOP-G5 | The Transform skips `okhttp3/`, `okio/`, `java/`, `javax/`, `android/`, `androidx/`, `kotlin*/`, `com/android/`. | Re-entering OkHttp's own internals creates infinite build loops; java.* classes are never in user jars anyway but the guard is cheap. |
| AOP-G6 | `NetScope.reportTx` / `reportRx` / `reportFlowEnd` are the only public-to-integration entry points into the aggregator. They short-circuit when `paused = true`. | Keeps the data path single-source-of-truth and cheap. |
| AOP-G7 | The plugin jar MUST be Java 8 bytecode (class file major 52). HMI's Gradle 6.7.1 runs on JDK 8 and will `UnsupportedClassVersionError` on major 55 (Java 11). | Enforced by `tasks.withType(KotlinCompile) { kotlinOptions.jvmTarget = '1.8' }`. |
| AOP-G8 | `compileOnly 'com.android.tools.build:gradle:4.2.2'` for the plugin. Any newer AGP API call (e.g. `AsmClassVisitorFactory`, `Artifacts`) will `ClassNotFoundException` on 4.2.2. | Legacy `com.android.build.api.transform.Transform` is the only portable path. |
| AOP-G9 | When re-computing class frames in `NetScopeTransform`, override `getCommonSuperClass` to fall back to `java/lang/Object` on `ClassNotFoundException`. | Build-time ASM doesn't have the app's ClassLoader; the default impl will throw on user classes. |

---

## 4. Playbooks

### 4.1 You got a field report: "traffic not being counted"

1. **Confirm the Transform ran.** `grep 'registered Transform' app/build/...` in the build log. If absent, the `indi.arrowyi.netscope` plugin was not applied in the consumer module.
2. **Confirm the instrumentation fired.** Inspect a known OkHttp caller class: `javap -c -p app/build/intermediates/transforms/netscope/.../MyActivity.class | grep NetScopeInterceptorInjector`. If absent, check the skip list (`shouldSkipClass` in [NetScopeTransform.kt](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt)) — the caller's package may be inadvertently excluded.
3. **Confirm the SDK is initialized.** `NetScope.status()` must return `ACTIVE`. If `NOT_INITIALIZED`, the consumer never called `NetScope.init(context)`.
4. **Confirm no one is wrapping twice.** `NetScope.getDomainStats()` showing ~2× the expected bytes → someone bypassed the marker. Grep for manual `addInterceptor(NetScopeInterceptor)` AND Transform-injected path both hitting the same builder.
5. **Ask whether the traffic is Java-side.** Telenav's `asdk.httpclient`, Chromium WebViews, native sockets opened via NDK — none of those are in scope. `total = NetScope.getTotalStats() + <their stats>` is the contract.

### 4.2 You want to add a new instrumentation target (e.g. Apache HttpClient)

Checklist:

1. Add a new `integration/` wrapper in `netscope-sdk` that implements `NetScopeInstrumented` and reports via `NetScope.reportTx/Rx/FlowEnd`.
2. Add a new `instrumenter/` class in `netscope-plugin` that rewrites the target call sites. Mirror `OkHttpBuilderInstrumenter` for method rewriting or `UrlConnectionInstrumenter` for DUP-before-invoke idioms.
3. Chain it into `tryTransform`'s ClassVisitor chain in [NetScopeTransform.kt](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt).
4. Update `shouldSkipClass()` if the target library's own package needs excluding (see AOP-G5).
5. Unit-test: feed a crafted call site through ASM, assert the rewritten bytecode contains `INVOKESTATIC indi/arrowyi/netscope/sdk/integration/...`.
6. Integration-test: apply the plugin to `app/`, make one call through the target library, assert `getDomainStats()` populated.

### 4.3 You are building on AGP 7.x / 8.x and want the new `AsmClassVisitorFactory` path

Keep the legacy Transform for AGP 4.2.2 users (HMI's Denali tree — AOP-G8). Add a sibling implementation behind an AGP version detector in `NetScopePlugin.apply`. Keep the instrumenter classes (they're pure ASM ClassVisitors — API-agnostic). Only the framing (Transform invocation / `AsmClassVisitorFactory.createClassVisitor`) differs.

### 4.4 JitPack publish fails

See `jitpack.yml`. Known issues:

- **AGP 7.4 prefab stderr bug** — not applicable here (no prefab), but the `env -u JAVA_TOOL_OPTIONS` preamble is still defensive against future tooling.
- **Gradle composite-build task path** — when JitPack builds the plugin, it must be targeted via its own build via the `--project-dir` / `./gradlew :build` style. Jitpack.yml handles both artifacts explicitly; do not "simplify" this.
- **R8 on consumer** — the HMI uses Proguard (R8 disabled). `consumer-rules.pro` keeps the `integration/` package. If the consumer ever enables R8, add the same rules to their `proguard-android-optimize.txt` chain.

---

## 5. API surface (post-refactor)

```kotlin
object NetScope {
    fun init(context: Context): Status         // ACTIVE, idempotent
    fun status(): Status                       // NOT_INITIALIZED / ACTIVE
    fun pause(); fun resume()
    fun clearStats(); fun markIntervalBoundary()
    fun getDomainStats(): List<DomainStats>
    fun getIntervalStats(): List<DomainStats>
    fun getTotalStats(): TotalStats            // sum across domains — HMI's primary
    fun setLogInterval(seconds: Int)
    fun setOnFlowEnd(cb: ((DomainStats) -> Unit)?)
    fun destroy()
}
```

Gone from the previous era: `setDebugMode`, `DEBUG_*`, `setStatusListener`, `getHookReport`, the full hook-health model. There is no partial / degraded / failed hook state in an AOP design.

---

## 6. Build and release

```bash
# SDK (Kotlin library)
./gradlew :netscope-sdk:assembleRelease

# Verify zero native libs in AAR (regression check)
unzip -l netscope-sdk/build/outputs/aar/netscope-sdk-release.aar | grep -E 'jni/|\.so' || echo "clean"

# Plugin (composite build — task addressing goes through the included build)
./gradlew -p netscope-plugin jar

# Plugin bytecode must be major 52 (Java 8)
javap -v netscope-plugin/build/classes/kotlin/main/indi/arrowyi/netscope/plugin/NetScopeTransform.class | head -3
# Expect: "major version: 52"

# Sample app end-to-end
./gradlew :app:assembleDebug

# Spot-check one instrumented consumer class
javap -c -p app/build/intermediates/transforms/netscope/debug/*/*/indi/arrowyi/netscope/app/MainActivity.class \
    | grep NetScopeInterceptorInjector
```

**Publishing**: JitPack watches tags + `main`. One build produces both artifacts. Because we publish two modules from a single repo, JitPack uses the **multi-module coordinate scheme** — the groupId is `com.github.Arrowyi.NetScope` (note the dot):

- `com.github.Arrowyi.NetScope:NetScope:<tag-or-sha>` — the AAR
- `com.github.Arrowyi.NetScope:NetScope-plugin:<tag-or-sha>` — the Gradle plugin jar

HMI consumes with:

```groovy
// root build.gradle buildscript
buildscript {
  repositories { maven { url 'https://jitpack.io' } }
  dependencies {
    classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v2.0.0'
  }
}

// app module
apply plugin: 'indi.arrowyi.netscope'   // AFTER AspectJ, per AOP-G4

dependencies {
  implementation 'com.github.Arrowyi.NetScope:NetScope:v2.0.0'
}
```

> Don't be tempted to rewrite the groupId to `com.github.Arrowyi` (single-colon form).
> That form would require splitting the plugin into its own GitHub repo. The
> multi-module form keeps both artifacts in one repo and one build log.

---

## 7. Things I wish someone had told me on day 1

- **The marker interface is the WHOLE idempotency story.** Don't add a parallel "have we already wrapped this?" mechanism. One source of truth.
- **Frame computation is where ASM bytes go wrong.** If you see `java.lang.VerifyError` at class load, the ClassWriter wasn't told to recompute frames, or `getCommonSuperClass` threw and wasn't caught.
- **OkHttp's `Response.body.source()`** returns a stable `BufferedSource`; wrapping it in a `lazy { ... .buffer() }` is correct and safe to call multiple times.
- **Kotlin jvmTarget = "1.8" isn't the default in recent Kotlin**. If the plugin jar shipped major 55 you'll get zero reported bugs — HMI will just silently fail to load it. Check your release artifact's bytecode version before every release.
- **`plugins { id 'indi.arrowyi.netscope' }` needs a `pluginManagement.includeBuild 'netscope-plugin'`** in `settings.gradle` for the same-repo consumer. External consumers use `classpath + apply plugin:`.
- **Bytehook is not coming back.** Read [BYTEHOOK_LESSONS.md](BYTEHOOK_LESSONS.md) before anyone talks you into "just one more hooker". On two independent devices the SDK's static footprint alone — not its runtime behaviour — was the trigger.

---

## Files to read before touching anything

1. This file.
2. [AOP_INTEGRATION.md](AOP_INTEGRATION.md) — the contract with integrators.
3. [BYTEHOOK_LESSONS.md](BYTEHOOK_LESSONS.md) — why the native path is retired.
4. [../netscope-sdk/src/main/kotlin/indi/arrowyi/netscope/sdk/NetScope.kt](../netscope-sdk/src/main/kotlin/indi/arrowyi/netscope/sdk/NetScope.kt) — runtime entry.
5. [../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt) — build-time control flow.

Good luck.
