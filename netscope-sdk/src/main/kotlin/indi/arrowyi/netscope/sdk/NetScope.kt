package indi.arrowyi.netscope.sdk

import android.content.Context
import android.util.Log
import indi.arrowyi.netscope.sdk.internal.SystemTrafficReader
import indi.arrowyi.netscope.sdk.internal.TrafficAggregator

/**
 * Entry point for NetScope traffic statistics.
 *
 * **Architecture (v3.0.0+):** two layers.
 *
 *   Layer A — [getTotalStats]: kernel-level *total* UID traffic since
 *   [init], obtained via [android.net.TrafficStats]. Includes
 *   everything the kernel counts for this process's UID: Java, Kotlin,
 *   C++, NDK, signed native blobs, raw sockets — whether or not
 *   NetScope's AOP layer saw it.
 *
 *   Layer B — [getApiStats] / [getIntervalStats]: per-API (host+path)
 *   application-layer counters populated by the Gradle plugin's ASM
 *   instrumentation of `OkHttpClient.Builder#build`,
 *   `HttpsURLConnection`, and `OkHttpClient#newWebSocket`. Java-layer
 *   only.
 *
 * **Breaking change from v2.x → v3.0.0:** `DomainStats` is gone;
 * `getDomainStats()` is gone. Use [ApiStats] / [getApiStats]. An API
 * key is `"$host$path"` where:
 *   - `host` = actual host, with `:port` folded in when it's
 *     non-default for the scheme (HTTPS 443 and HTTP 80 stay elided).
 *     Raw IPs like `192.168.1.5:9000` show up verbatim. Connections we
 *     can't resolve show `<unknown>` (optionally `<unknown>:port`).
 *   - `path` = URL path with numeric IDs → `:id`, UUIDs → `:uuid`,
 *     long hex strings → `:hash`. Query/fragment stripped.
 *
 *   `sum(getApiStats().tx) <= getTotalStats().txTotal` is intentional
 *   — the gap is "non-instrumented traffic", mostly native. HMIs may
 *   surface this gap if useful.
 *
 * Thread-safe. All methods may be called from any thread.
 */
object NetScope {

    private const val TAG = "NetScope"

    internal val aggregator = TrafficAggregator()

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
     * Clears per-API AOP counters (Layer B) AND re-captures the
     * Layer-A kernel baseline, so both totals and per-API numbers
     * restart from zero.
     */
    @Synchronized
    fun clearStats() {
        aggregator.clear()
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

    /**
     * Uninstall runtime state (stop the log reporter, clear the flow-end
     * callback). Instrumentation stays in place — to truly remove it,
     * rebuild without the `indi.arrowyi.netscope` Gradle plugin.
     */
    @Synchronized
    fun destroy() {
        LogcatReporter.stop()
        flowEndCallback = null
        initialized = false
    }
}
