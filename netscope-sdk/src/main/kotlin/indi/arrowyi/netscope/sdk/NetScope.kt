package indi.arrowyi.netscope.sdk

import android.content.Context
import android.util.Log
import indi.arrowyi.netscope.sdk.internal.TrafficAggregator

/**
 * Entry point for NetScope per-domain Java/Android traffic statistics.
 *
 * **Architecture:** NetScope is a pure Kotlin/Java AOP library. Traffic
 * is observed by wrapping the standard Android HTTP stacks
 * (OkHttp / HttpsURLConnection / OkHttp WebSocket). Host apps integrate
 * by applying the `indi.arrowyi.netscope` Gradle plugin, which
 * instruments all call sites at build time. No runtime code change is
 * needed in host sources.
 *
 * **Scope:** Only Java-layer traffic is observed. Native HTTP clients
 * (e.g. Telenav `asdk.httpclient`) report their own stats. The HMI is
 * expected to present the sum:
 *
 * ```
 *   total = NetScope.getTotalStats() + <native stack stats>
 * ```
 *
 * The previous native / bytehook backend is retired; see
 * `docs/BYTEHOOK_LESSONS.md` for the postmortem.
 *
 * Thread-safe. All methods may be called from any thread.
 */
object NetScope {

    private const val TAG = "NetScope"

    internal val aggregator = TrafficAggregator()

    @Volatile private var initialized: Boolean = false
    @Volatile private var flowEndCallback: ((DomainStats) -> Unit)? = null

    /**
     * Initialise NetScope. Idempotent.
     *
     * In the current AOP architecture `init` has no failure mode —
     * instrumentation is done at build time, and this call merely flips
     * the runtime state to [Status.ACTIVE].
     */
    @Synchronized
    fun init(context: Context): Status {
        if (initialized) return Status.ACTIVE
        initialized = true
        Log.i(TAG, "initialised (AOP runtime; native hooks retired)")
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

    /** Reset all collected stats. */
    fun clearStats() { aggregator.clear() }

    /**
     * Flush current-interval counters into the interval snapshot and
     * start a new interval window. Called automatically by
     * [setLogInterval].
     */
    fun markIntervalBoundary() { aggregator.markIntervalBoundary() }

    /**
     * Cumulative stats since [init] / last [clearStats], sorted by
     * total bytes descending.
     */
    fun getDomainStats(): List<DomainStats> =
        aggregator.getDomainStats().sortedByDescending { it.totalBytes }

    /**
     * Stats for the last completed interval (since last
     * [markIntervalBoundary]), sorted by interval bytes desc.
     */
    fun getIntervalStats(): List<DomainStats> =
        aggregator.getIntervalStats()
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }

    /**
     * Aggregated total across all domains. Primary API for HMIs that
     * want to sum this with a native stack's own reported stats.
     */
    fun getTotalStats(): TotalStats = aggregator.getTotalStats()

    /**
     * Enable periodic Logcat output (tag: `NetScope`). Each print also
     * calls [markIntervalBoundary]. Pass 0 to disable.
     */
    fun setLogInterval(seconds: Int) {
        if (seconds > 0) LogcatReporter.start(seconds) else LogcatReporter.stop()
    }

    /**
     * Register a callback invoked whenever one logical flow terminates
     * (HTTP response drained / closed connection). The [DomainStats]
     * passed in has `txBytesInterval` / `rxBytesInterval` reflecting
     * just that one flow.
     */
    fun setOnFlowEnd(callback: ((DomainStats) -> Unit)?) {
        flowEndCallback = callback
    }

    /** Internal: accessed by integration wrappers when a flow closes. */
    internal fun reportFlowEnd(domain: String, txIncrement: Long, rxIncrement: Long) {
        aggregator.flowEnded(domain, txIncrement, rxIncrement, flowEndCallback)
    }

    /** Internal: add tx bytes for a domain. */
    internal fun reportTx(domain: String, bytes: Long) {
        aggregator.addTx(domain, bytes)
    }

    /** Internal: add rx bytes for a domain. */
    internal fun reportRx(domain: String, bytes: Long) {
        aggregator.addRx(domain, bytes)
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
