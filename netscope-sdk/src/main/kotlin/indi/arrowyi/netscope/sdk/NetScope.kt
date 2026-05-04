package indi.arrowyi.netscope.sdk

import android.content.Context
import android.util.Log
import indi.arrowyi.netscope.sdk.internal.CppTrafficAggregator
import indi.arrowyi.netscope.sdk.internal.EndpointFormatter
import indi.arrowyi.netscope.sdk.internal.PathNormalizer
import indi.arrowyi.netscope.sdk.internal.SystemTrafficReader
import indi.arrowyi.netscope.sdk.internal.TrafficAggregator

/**
 * Entry point for NetScope traffic statistics.
 *
 * **Architecture:** four layers (v4.0 adds Layers C and D).
 *
 *   Layer A — [getTotalStats]: kernel-level *total* UID traffic since [init],
 *   obtained via [android.net.TrafficStats]. Covers Java, Kotlin, C++, NDK,
 *   raw sockets — everything the kernel counts for this UID.
 *
 *   Layer B — [getApiStats] / [getIntervalStats]: per-API (host+path) counters
 *   populated by the Gradle plugin's ASM instrumentation of OkHttp, URLConnection,
 *   and WebSocket call sites. Java-layer only.
 *
 *   Layer C — [getCppApiStats]: per-API counters populated by C++ HTTP client
 *   callbacks. Requires integration of the HMI native bridge (see
 *   `docs/cpp-bridge/`) that calls [reportCppFlow] via JNI. Uses
 *   `tn::http::client::restricted::injectGlobalOption`.
 *
 *   Layer D — provided by the optional `netscope-hook` module ([NetScopeHook]).
 *   PLT-level socket hooks that capture ALL TCP traffic by remote IP:port,
 *   including traffic from C++ HTTP clients that are not instrumented by
 *   Layers B or C. See [NetScopeHook.getSocketStats].
 *
 * **Validation relationship** (not additive — each layer is a different view):
 * ```
 *   sum(Layer D bytes) ≈ Layer A total      // D covers all sockets
 *   sum(Layer B) + sum(Layer C) ≈ sum(Layer D)  // B+C attribution should explain D
 *   Gap = Layer A - Layer B - Layer C       // non-attributed native traffic
 * ```
 *
 * Thread-safe. All methods may be called from any thread.
 */
object NetScope {

    private const val TAG = "NetScope"

    internal val aggregator = TrafficAggregator()
    internal val cppAggregator = CppTrafficAggregator()

    @Volatile private var initialized: Boolean = false
    @Volatile private var flowEndCallback: ((ApiStats) -> Unit)? = null

    // Layer-A (kernel) baseline captured at init(). getTotalStats()
    // returns (currentReading - baseline) so numbers are "since init".
    @Volatile private var baselineTx: Long = 0L
    @Volatile private var baselineRx: Long = 0L

    @Volatile private var reader: SystemTrafficReader = SystemTrafficReader.DEFAULT

    /** Test-only seam. Installs a fake [SystemTrafficReader]. */
    internal fun installReaderForTest(r: SystemTrafficReader) {
        reader = r
    }

    /**
     * Initialise NetScope. Idempotent.
     *
     * First successful call:
     *   - clears per-API AOP counters (Layer B),
     *   - captures a kernel-level tx/rx baseline (Layer A), so
     *     [getTotalStats] numbers are "since init" rather than
     *     "since device boot".
     *
     * Subsequent calls while already initialised are no-ops.
     */
    @Synchronized
    fun init(@Suppress("UNUSED_PARAMETER") context: Context): Status {
        if (initialized) return Status.ACTIVE
        aggregator.clear()
        val tx = reader.getUidTxBytes()
        val rx = reader.getUidRxBytes()
        baselineTx = if (tx == SystemTrafficReader.UNSUPPORTED) 0L else tx
        baselineRx = if (rx == SystemTrafficReader.UNSUPPORTED) 0L else rx
        initialized = true
        Log.i(
            TAG,
            "initialised (AOP runtime; API counters reset; " +
                "baselineTx=$baselineTx rx=$baselineRx)"
        )
        return Status.ACTIVE
    }

    /** Current SDK state. */
    fun status(): Status = if (initialized) Status.ACTIVE else Status.NOT_INITIALIZED

    /**
     * Pause byte counting. Instrumentation wrappers stay in place but
     * their increments become no-ops.
     */
    fun pause() { aggregator.setPaused(true) }

    /** Resume byte counting after [pause]. */
    fun resume() { aggregator.setPaused(false) }

    /**
     * Reset all collected stats.
     *
     * Clears Layer B (AOP) and Layer C (C++ callback) counters AND
     * re-captures the Layer-A kernel baseline, so all totals restart from zero.
     * Layer D (socket hook) stats are managed separately via [NetScopeHook].
     */
    @Synchronized
    fun clearStats() {
        aggregator.clear()
        cppAggregator.clear()
        if (initialized) {
            val tx = reader.getUidTxBytes()
            val rx = reader.getUidRxBytes()
            baselineTx = if (tx == SystemTrafficReader.UNSUPPORTED) 0L else tx
            baselineRx = if (rx == SystemTrafficReader.UNSUPPORTED) 0L else rx
        }
    }

    /**
     * Flush current-interval counters into the interval snapshot and
     * start a new interval window. Called automatically by
     * [setLogInterval].
     */
    fun markIntervalBoundary() { aggregator.markIntervalBoundary() }

    /**
     * Cumulative stats since [init] / last [clearStats], sorted by
     * total bytes descending. Each entry is one (host, path) tuple.
     */
    fun getApiStats(): List<ApiStats> =
        aggregator.getApiStats().sortedByDescending { it.totalBytes }

    /**
     * Stats for the last completed interval (since last
     * [markIntervalBoundary]), sorted by interval bytes desc.
     */
    fun getIntervalStats(): List<ApiStats> =
        aggregator.getIntervalStats()
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }

    /**
     * Aggregated total traffic since [init], in bytes.
     *
     * Source: `android.net.TrafficStats.getUid{Tx,Rx}Bytes(myUid)`
     * minus the baseline captured at [init]. Covers all traffic the
     * kernel counts for our UID — Java, native, NDK, C++ — not just
     * what NetScope's AOP instrumentation observed. `sum(getApiStats())`
     * will be `<=` this number; the gap is non-instrumented traffic.
     *
     * `connCountTotal` remains a Java-layer count (OkHttp /
     * HttpURLConnection flow ends) — the kernel has no notion of
     * "connection close" for native sockets.
     *
     * Fallback: on pre-Q OEM kernels that return
     * [android.net.TrafficStats.UNSUPPORTED], this falls back to the
     * AOP sum so the UI is not blank.
     *
     * Not gated by [pause] — the kernel keeps counting regardless.
     */
    fun getTotalStats(): TotalStats {
        if (!initialized) return TotalStats(0L, 0L, 0)
        val curTx = reader.getUidTxBytes()
        val curRx = reader.getUidRxBytes()
        if (curTx == SystemTrafficReader.UNSUPPORTED
            || curRx == SystemTrafficReader.UNSUPPORTED
        ) {
            return aggregator.getTotalStats()
        }
        // Reboot-wrap guard: kernel counters go back to 0 after reboot.
        // The process would normally die too, but if for any reason the
        // baseline is higher than the current reading we re-baseline so
        // subsequent reads are non-negative.
        if (curTx < baselineTx) baselineTx = 0L
        if (curRx < baselineRx) baselineRx = 0L
        val connTotal = aggregator.getTotalStats().connCountTotal
        return TotalStats(
            txTotal = curTx - baselineTx,
            rxTotal = curRx - baselineRx,
            connCountTotal = connTotal
        )
    }

    /**
     * Enable periodic Logcat output (tag: `NetScope`). Each print also
     * calls [markIntervalBoundary]. Pass 0 to disable.
     */
    fun setLogInterval(seconds: Int) {
        if (seconds > 0) LogcatReporter.start(seconds) else LogcatReporter.stop()
    }

    /**
     * Register a callback invoked whenever one logical flow terminates
     * (HTTP response drained / closed connection). The [ApiStats]
     * passed in has `txBytesInterval` / `rxBytesInterval` reflecting
     * just that one flow.
     */
    fun setOnFlowEnd(callback: ((ApiStats) -> Unit)?) {
        flowEndCallback = callback
    }

    // ─── Internal API used by the generated wrappers ─────────────────
    //
    // Callers are the classes under `integration/`, which already ran
    // `EndpointFormatter.format(...)` and `PathNormalizer.normalize(...)`
    // on their inputs. The aggregator stores these strings verbatim —
    // it does not re-normalise — which keeps the hot path allocation-free.

    /** Internal: flow terminated (response closed, URLConnection input drained, WS closed). */
    internal fun reportFlowEnd(host: String, path: String, txIncrement: Long, rxIncrement: Long) {
        aggregator.flowEnded(host, path, txIncrement, rxIncrement, flowEndCallback)
    }

    /** Internal: add tx bytes. */
    internal fun reportTx(host: String, path: String, bytes: Long) {
        aggregator.addTx(host, path, bytes)
    }

    /** Internal: add rx bytes. */
    internal fun reportRx(host: String, path: String, bytes: Long) {
        aggregator.addRx(host, path, bytes)
    }

    // ─── Layer C: C++ HTTP client stats ─────────────────────────────────────
    //
    // Populated by the HMI's native bridge code calling reportCppFlow via JNI.
    // The bridge hooks tn::http::client::restricted::injectGlobalOption and
    // forwards each completed request here. See docs/cpp-bridge/ for the
    // reference implementation.

    /**
     * Cumulative per-API stats from C++ HTTP client callbacks (Layer C).
     *
     * Each entry represents one (host, path) tuple observed by the C++ HTTP
     * client. Independent of [getApiStats] (Layer B); both may record the same
     * endpoint when both Java and C++ stacks talk to it — that is expected
     * and useful for cross-validation.
     *
     * Returns an empty list until the HMI native bridge calls [reportCppFlow].
     * Sorted by total bytes descending.
     */
    fun getCppApiStats(): List<CppApiStats> =
        cppAggregator.getCppApiStats().sortedByDescending { it.totalBytes }

    /**
     * Reset Layer C counters. Does not affect Layer A, B, or D.
     */
    fun clearCppApiStats() { cppAggregator.clear() }

    /**
     * Entry point called from the HMI's native bridge via JNI when a C++
     * HTTP request completes. Parses `rawUrl` into (host, path) using the
     * same [EndpointFormatter] and [PathNormalizer] rules as Layer B.
     *
     * Not intended to be called directly by Kotlin/Java application code.
     * Use the `docs/cpp-bridge/` reference implementation for the C++ side.
     *
     * @param rawUrl   full URL string as reported by `tn::http::client` (e.g.
     *                 `https://api.example.com:8080/v1/users/123`).
     * @param txBytes  bytes sent for this request (>= 0).
     * @param rxBytes  bytes received in the response (>= 0).
     * @param durationMs total transfer time in milliseconds (>= 0).
     */
    @JvmStatic
    fun reportCppFlow(rawUrl: String, txBytes: Long, rxBytes: Long, durationMs: Double) {
        if (!initialized) return
        val (host, path) = parseUrl(rawUrl)
        cppAggregator.report(host, path, txBytes, rxBytes, durationMs)
    }

    /**
     * Uninstall runtime state (stop the log reporter, clear the flow-end
     * callback). Instrumentation stays in place — to truly remove it,
     * rebuild without the `indi.arrowyi.netscope` Gradle plugin.
     */
    @Synchronized
    fun destroy() {
        LogcatReporter.stop()
        flowEndCallback = null
        cppAggregator.clear()
        initialized = false
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    /**
     * Parse a raw URL into (host, path) using the same normalisation rules
     * as the AOP layer. Returns (<unknown>, /) on any malformed input rather
     * than throwing.
     */
    private fun parseUrl(rawUrl: String): Pair<String, String> {
        return try {
            val url = java.net.URL(rawUrl)
            val defaultPort = when (url.protocol.lowercase()) {
                "https", "wss" -> 443
                "http", "ws"   -> 80
                else           -> -1
            }
            val host = EndpointFormatter.format(url.host, url.port, defaultPort)
            val path = PathNormalizer.normalize(url.path.ifEmpty { "/" })
            Pair(host, path)
        } catch (_: Exception) {
            Pair(EndpointFormatter.UNKNOWN_HOST, "/")
        }
    }
}
