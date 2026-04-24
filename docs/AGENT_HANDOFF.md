# NetScope — Agent Handoff

> Read this first if you are picking up NetScope maintenance — whether
> as a human engineer or an AI coding assistant. It is a distilled,
> action-oriented briefing for the current (post-2026-04-24) design:
> **pure Kotlin/Java AOP runtime + a Gradle Transform plugin**.
>
> The prior native/bytehook era is retired. See
> [BYTEHOOK_LESSONS.md](BYTEHOOK_LESSONS.md) for the postmortem and
> [HOOK_EVOLUTION.md](HOOK_EVOLUTION.md) for the historical chronicle.

## Changelog

### v3.0.1 (2026-04-24)

One behaviour fix. `URLConnection` users are rewritten by the Transform
regardless of scheme, so at runtime we also saw `file:`, `content:`,
`asset:`, `data:`, `android.resource:`, and `jar:file:…` streams
flowing through `NetScopeUrlConnection.wrapInputStream`. Those are
**local** sources, never touch the radio, and must not be attributed
as network traffic.

v3.0.1 adds a local-scheme denylist (new rule **AOP-G16**). The policy
is "skip if local" rather than "only allow http(s)" — that keeps
genuine over-the-wire transports like `ftp:`, `sftp:`, and any custom
socket-backed scheme counted. `jar:` is resolved by inner URL, so
`jar:file:/…` is local but `jar:http://cdn/…!/x` counts.

Coordinates: `com.github.Arrowyi.NetScope:NetScope:v3.0.1` and
`com.github.Arrowyi.NetScope:NetScope-plugin:v3.0.1`. Pure SDK change,
plugin bytecode unchanged — version bumped in lockstep for clarity.

### v3.0.0 (2026-04-24) — BREAKING

Per-domain (`host`) becomes **per-API (`host` + `path`)**. The v2.x
data model called out every entry as a `DomainStats` keyed on one
hostname. That is insufficient for HMIs that need to tell which
endpoint on a shared host is expensive — `/v1/location` vs
`/v1/map-tiles` on `api.example.com` both rolled up to one row.

v3.0.0 introduces:

1. **`ApiStats`**, the new data class. Fields: `host`, `path`, `key`
   (`= "$host$path"`), plus all the byte/conn/time counters that
   `DomainStats` had. `DomainStats` is removed.
2. **`NetScope.getApiStats()`** replaces `getDomainStats()`.
   `getIntervalStats()` keeps its name but changes element type.
   `setOnFlowEnd` receives an `ApiStats`.
3. **Host with port-fallback.** The `host` field of `ApiStats` is the
   formatted endpoint — raw host when the scheme default port is in
   use (HTTPS `:443` / HTTP `:80` elided), or `host:port` for anything
   else. Raw IPs pass through verbatim (`192.168.1.5:9000`). If the
   URL has no resolvable host at all we emit `<unknown>` (optionally
   `<unknown>:port`). `EndpointFormatter` is the single choke-point.
4. **Path normalization.** Paths go through `PathNormalizer`:
   numeric IDs → `:id`, UUIDs → `:uuid`, long hex strings → `:hash`,
   query/fragment stripped, consecutive slashes collapsed, trailing
   slash dropped, missing leading `/` added. So `/users/123/posts/456`
   becomes `/users/:id/posts/:id` and `GET /foo` merges with
   `POST /foo`.
5. **Bytecode change (callers must rebuild).** The
   `OkHttpWebSocketInstrumenter` now pushes a 3-arg `wrapListener`
   and a 3-arg `wrapWebSocket` (endpoint, path, x). Plugin v3.0.0
   paired with SDK ≤ v2.x (or vice versa) will fail at link time
   with `NoSuchMethodError`. Coordinate version bumps accordingly.

### Golden rule update — AOP-G14

`getApiStats()` returns ONE row per `(host, path)` tuple. If you're
about to add a new granularity knob (query string? header? method?)
stop and re-read the brainstorming notes under
`docs/superpowers/specs/` first — v3.0.0 deliberately keeps the
aggregation key to two strings so the in-memory footprint stays flat
even for HMIs that talk to dozens of APIs. New granularity should be
opt-in via a pluggable `PathNormalizer` interface, not a fourth key
dimension in the hot path.

### Golden rule update — AOP-G15

`EndpointFormatter` owns the canonical host-string shape. Integration
wrappers (`NetScopeInterceptor`, `NetScopeUrlConnection`,
`NetScopeWebSocket`) MUST NOT format hosts themselves. Any new
integration point (raw socket, Retrofit converter, ...) must resolve
`(host, port, defaultPortForScheme)` and hand them to
`EndpointFormatter.format(...)`. Centralising this keeps dedupe across
sources working (an OkHttp hit to `api.example.com:443` must collapse
with an HttpsURLConnection hit to the same address).

Coordinates: `com.github.Arrowyi.NetScope:NetScope:v3.0.0` and
`com.github.Arrowyi.NetScope:NetScope-plugin:v3.0.0`.

### v2.0.3 (2026-04-24)

One build-breaker fix consumers should know about:

**Cross-scope duplicate-class dedupe (AOP-G13).** v2.0.2 declared
`SCOPE_FULL_PROJECT` (= PROJECT + SUB_PROJECTS + EXTERNAL_LIBRARIES)
as its **main** scope. When AGP 4.x sees `EXTERNAL_LIBRARIES` in a
Transform's main scope, it funnels every external AAR's classes into
a single `mixed_scope_dex_archive/` bucket and the downstream
`DexMergingTask` then runs one merge invocation on that whole bucket.
This collapses the per-scope dedupe that normally keeps cross-module
same-named classes apart — on Denali, two
`com.telenav.auto.dr.BuildConfig` (one from the local `:dr` module,
one from a vendor `:dr` AAR with the same manifest `package`)
suddenly collided with `D8: Type ... is defined multiple times`.

The naive fix would be to drop `EXTERNAL_LIBRARIES` from the main
scope. We considered it and rejected it: HMIs ship large vendor AARs
(e.g. `:search`, `:map`) whose network traffic dominates their
totals. Dropping `EXTERNAL_LIBRARIES` would mean those call sites
never get a NetScope interceptor attached and `getDomainStats()`
silently under-reports.

v2.0.3 instead reproduces AGP's per-scope dedupe *inside* the
Transform. We keep the full `{PROJECT, SUB_PROJECTS,
EXTERNAL_LIBRARIES}` scope, then process inputs in
`PROJECT > SUB_PROJECTS > EXTERNAL_LIBRARIES` order, tracking the
internal class names we have already emitted. When a later
lower-priority input carries a class name we have already seen, we
drop it. This matches what AGP's baseline DexMergingTask would have
done under scope-split routing — the higher-priority copy wins — so
D8 no longer sees the duplicate. Vendor-AAR OkHttp / URL /
WebSocket call sites are still rewritten.

Trade-off: the Transform is now non-incremental (dedupe needs a
fresh global seen-set every run). The hot path is still dominated
by the v2.0.2 [needsRewrite] prefilter, so this is a few seconds
cost on full builds, not minutes.

Coordinates: `com.github.Arrowyi.NetScope:NetScope:v2.0.3` and
`com.github.Arrowyi.NetScope:NetScope-plugin:v2.0.3`. No API or
runtime-semantics changes from v2.0.2 — this is a build-system-only
fix.

### v2.0.2 (2026-04-24)

Two behaviour changes consumers should know about:

1. **D8 / dexing crash fix (AOP-G10 / AOP-G11).** v2.0.1 rewrote every
   class through `ClassReader → ClassVisitor chain → ClassWriter`
   regardless of whether the class contained a target call site.
   That round-trip is *not* byte-for-byte identical (ASM normalises
   constant pool order, attribute emission, etc.) and produced
   `Invalid descriptor char 'N'` when D8 tried to dex some untouched
   business classes on Denali. `NetScopeTransform.tryTransform()` now
   prefilters with a readonly `needsRewrite()` visitor — only classes
   that actually call one of the three targets are rewritten. The
   `ClassWriter` flag was also downgraded from `COMPUTE_FRAMES` to
   `COMPUTE_MAXS`, removing the need for the `getCommonSuperClass`
   fallback.

2. **`getTotalStats()` now returns kernel-level UID traffic
   (AOP-G12).** Previously it returned `sum(AOP domains)`, which
   invisibly missed traffic from native HTTP clients. It now reads
   `android.net.TrafficStats.getUid{Tx,Rx}Bytes(myUid)` minus a
   baseline captured at `init()`, so the number covers Java + native
   + NDK. `getDomainStats()` remains AOP-only (Java HTTP/S). HMIs can
   compute `total.totalBytes - sum(getDomainStats().totalBytes)` to
   surface the un-attributed gap. Pre-Q OEM kernels returning
   `TrafficStats.UNSUPPORTED` transparently fall back to the AOP sum.

Coordinates: `com.github.Arrowyi.NetScope:NetScope:v2.0.2` and
`com.github.Arrowyi.NetScope:NetScope-plugin:v2.0.2`.

---

## 1. What NetScope is, now

NetScope is an Android SDK that reports, with zero source changes to
the host app:

- **Layer A — total kernel-level UID traffic since `init()`**, obtained
  from `android.net.TrafficStats.getUid{Tx,Rx}Bytes` minus a baseline
  captured at `init()`. Covers Java + native + NDK + raw sockets.
- **Layer B — per-API (host + path) Java-layer breakdown** (v3.0.0+),
  obtained from build-time ASM instrumentation of OkHttp,
  HttpsURLConnection, and OkHttp WebSocket call sites.

```
sum(getApiStats().tx)  <=  getTotalStats().txTotal
```

The gap is non-instrumented traffic (most often a native HTTP client).
HMIs that care about attribution render the gap explicitly. HMIs that
just want "total app traffic" read `getTotalStats()` directly — it now
subsumes the old `total = NetScope.getTotalStats() + <native stack>`
formula.

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
│       ├── NetScope.kt           ← public entry point (Layer A + Layer B)
│       ├── Status.kt             ← { NOT_INITIALIZED, ACTIVE }
│       ├── ApiStats.kt           ← per-API (host+path) row (Layer B, data class, v3.0.0+)
│       ├── TotalStats.kt         ← kernel-level UID total (Layer A)
│       ├── LogcatReporter.kt     ← optional periodic adb logcat
│       ├── internal/
│       │   ├── TrafficAggregator.kt   ← per-API AtomicLong counters (keyed host\u0000path)
│       │   ├── EndpointFormatter.kt   ← host[:port] / <unknown> fallback (v3.0.0+)
│       │   ├── PathNormalizer.kt      ← :id / :uuid / :hash templating (v3.0.0+)
│       │   └── SystemTrafficReader.kt ← TrafficStats seam (testable)
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
| AOP-G9 | (OBSOLETE after v2.0.2) Don't use `ClassWriter.COMPUTE_FRAMES` in `NetScopeTransform`. Use `COMPUTE_MAXS` only, and never rewrite a class that doesn't contain a target call site (see G10). | The `getCommonSuperClass` fallback used to be the workaround; G10 + G11 together remove the need. |
| AOP-G10 | `NetScopeTransform.tryTransform()` MUST prefilter with the readonly `needsRewrite()` visitor and return `null` (= byte-for-byte passthrough) when the class contains none of our three target `INVOKEVIRTUAL`s. | v2.0.1 piped every class through `ClassReader -> ClassWriter` unconditionally, which is *not* byte-for-byte identical even when no visitor changed anything. On HMI Denali, that produced classes D8 refused with `Invalid descriptor char 'N'`. |
| AOP-G11 | `ClassWriter` must be built with `COMPUTE_MAXS`, not `COMPUTE_FRAMES`. Our instrumenters only insert straight-line `INVOKESTATIC` + `DUP` sequences; they never add branch targets or new frame-crossing types. | `COMPUTE_FRAMES` forces ASM into `getCommonSuperClass()`, which runs `Class.forName(...)` on user classes through the plugin's classloader — those aren't visible there, wrong answers silently corrupt the StackMapTable, and D8 later trips on the dex frame table. |
| AOP-G12 | `getTotalStats()` reads kernel-level `TrafficStats.getUid{Tx,Rx}Bytes(myUid)` minus a baseline captured at `init()`. `getApiStats()` stays AOP-only. By design `sum(getApiStats().tx) <= getTotalStats().txTotal`. | Historical `getTotalStats()` was `sum(AOP)` — invisible to native HTTP clients. v2.0.2 gives HMIs the kernel truth without us shipping a native library. |
| AOP-G13 | `NetScopeTransform.getScopes()` is `{PROJECT, SUB_PROJECTS, EXTERNAL_LIBRARIES}` AND `transform()` implements scope-priority dedupe on class internal names (`PROJECT > SUB_PROJECTS > EXTERNAL_LIBRARIES`). The Transform is non-incremental. Never "simplify" the dedupe away or switch back to incremental. | Two opposing forces. (a) HMIs ship vendor AARs (`:search`, `:map`) with heavy HTTP — dropping EXTERNAL_LIBRARIES from scope under-reports Layer B. (b) When EXTERNAL_LIBRARIES is a main scope on AGP 4.x, all inputs collapse into `mixed_scope_dex_archive/` and AGP's default per-scope dedupe stops working, so cross-module same-named classes (e.g. two `com.foo.BuildConfig` from a local module and a vendor AAR) collide with `D8: Type ... is defined multiple times`. Doing the dedupe ourselves, in priority order, is the only way to keep both properties. Incremental builds would need a persisted seen-set which adds fragility without much win. |
| AOP-G14 | The `(host, path)` tuple is the ONLY aggregation key in the hot path. New granularity dimensions (method, query, header, …) must go through a pluggable `PathNormalizer`-style interface, not a third hash-map key. | Aggregator footprint is linear in the number of distinct keys. A fourth dimension doubles memory budget for every HMI that talks to dozens of APIs — unacceptable on constrained head-units. |
| AOP-G15 | All host-string formatting goes through `EndpointFormatter.format(host, port, defaultPort)`. Integration wrappers MUST NOT concatenate `host` + `:port` themselves, and MUST NOT invent their own `<unknown>` fallback. | Centralising this keeps dedupe across sources working. If an OkHttp call and an HttpsURLConnection call both target `api.example.com:443`, they must collapse to the same `host` string (`api.example.com`) — a local format bug anywhere in the integration layer silently splits them. |
| AOP-G16 | Only **network** URLs are counted by `NetScopeUrlConnection`. Local-scheme denylist: `file`, `content`, `asset`, `android.resource`, `android-app`, `data`, `res`, `resource`. `jar:` is resolved by inner URL. Everything else (including `ftp`, `sftp`, `gopher`, custom socket-backed schemes) is treated as network. The policy is denylist, not allowlist: if a new over-the-wire transport shows up (e.g. `quic:`), it should be counted by default. | The Transform rewrites `URLConnection.getInputStream()` unconditionally, so at runtime we also receive streams for local-filesystem reads, ContentProvider queries, asset pipes, and data URIs. Attributing those as network traffic produces spurious `<unknown>/data/app/…` rows and inflates `sum(ApiStats.tx)` well past `getTotalStats().txTotal`. A denylist (rather than an http/https allowlist) ensures genuine network transports aren't silently dropped. |

---

## 4. Playbooks

### 4.1 You got a field report: "traffic not being counted"

1. **Confirm the Transform ran.** `grep 'registered Transform' app/build/...` in the build log. If absent, the `indi.arrowyi.netscope` plugin was not applied in the consumer module.
2. **Confirm the instrumentation fired.** Inspect a known OkHttp caller class: `javap -c -p app/build/intermediates/transforms/netscope/.../MyActivity.class | grep NetScopeInterceptorInjector`. If absent, check the skip list (`shouldSkipClass` in [NetScopeTransform.kt](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt)) — the caller's package may be inadvertently excluded.
3. **Confirm the SDK is initialized.** `NetScope.status()` must return `ACTIVE`. If `NOT_INITIALIZED`, the consumer never called `NetScope.init(context)`.
4. **Confirm no one is wrapping twice.** `NetScope.getApiStats()` showing ~2× the expected bytes → someone bypassed the marker. Grep for manual `addInterceptor(NetScopeInterceptor)` AND Transform-injected path both hitting the same builder.
5. **Ask whether the traffic is Java-side.** Telenav's `asdk.httpclient`, Chromium WebViews, native sockets opened via NDK — none of those are in scope. `total = NetScope.getTotalStats() + <their stats>` is the contract.

### 4.2 You want to add a new instrumentation target (e.g. Apache HttpClient)

Checklist:

1. Add a new `integration/` wrapper in `netscope-sdk` that implements `NetScopeInstrumented` and reports via `NetScope.reportTx/Rx/FlowEnd`.
2. Add a new `instrumenter/` class in `netscope-plugin` that rewrites the target call sites. Mirror `OkHttpBuilderInstrumenter` for method rewriting or `UrlConnectionInstrumenter` for DUP-before-invoke idioms.
3. Chain it into `tryTransform`'s ClassVisitor chain in [NetScopeTransform.kt](../netscope-plugin/src/main/kotlin/indi/arrowyi/netscope/plugin/NetScopeTransform.kt).
4. Update `shouldSkipClass()` if the target library's own package needs excluding (see AOP-G5).
5. Unit-test: feed a crafted call site through ASM, assert the rewritten bytecode contains `INVOKESTATIC indi/arrowyi/netscope/sdk/integration/...`.
6. Integration-test: apply the plugin to `app/`, make one call through the target library, assert `getApiStats()` populated with the expected `(host, path)` key.

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
    fun getApiStats(): List<ApiStats>          // Layer B: AOP per (host, path)  — v3.0.0+
    fun getIntervalStats(): List<ApiStats>     // Layer B: last interval          — v3.0.0+
    fun getTotalStats(): TotalStats            // Layer A: kernel UID total since init()
    fun setLogInterval(seconds: Int)
    fun setOnFlowEnd(cb: ((ApiStats) -> Unit)?)
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
    classpath 'com.github.Arrowyi.NetScope:NetScope-plugin:v3.0.1'
  }
}

// app module
apply plugin: 'indi.arrowyi.netscope'   // AFTER AspectJ, per AOP-G4

dependencies {
  implementation 'com.github.Arrowyi.NetScope:NetScope:v3.0.1'
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
