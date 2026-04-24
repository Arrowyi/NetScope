package indi.arrowyi.netscope.sdk.internal

import indi.arrowyi.netscope.sdk.ApiStats
import indi.arrowyi.netscope.sdk.TotalStats
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * In-process per-API traffic counters (v3.0.0+).
 *
 * The aggregator keys on the tuple `(host, path)`:
 *   - `host` is the already-formatted endpoint string produced by
 *     [EndpointFormatter] (may include `:port`, may be
 *     `<unknown>` / `<unknown>:port` for unresolvable connections).
 *   - `path` is a normalised URL path produced by [PathNormalizer]
 *     (templated IDs / UUIDs / hashes, always starts with `/`).
 *
 * Concurrency:
 *  - Every API key has its own [ApiCounter] holding AtomicLong counters
 *    for tx/rx (cumulative and current-interval) and an AtomicInteger
 *    for closed-flow count. All increments are lock-free.
 *  - The map is a [ConcurrentHashMap]; `computeIfAbsent` installs new
 *    counters atomically.
 *  - Interval boundaries are taken under [snapshotLock] to make
 *    "snapshot then reset" one atomic step relative to readers of
 *    [getIntervalStats]. Writers (addTx/addRx) do NOT take this lock —
 *    they atomically add to both cumulative and interval counters; a
 *    boundary racing with an addTx may attribute the bytes to the new
 *    interval. Over long time scales this is a rounding error.
 */
internal class TrafficAggregator {

    private class ApiCounter(val host: String, val path: String) {
        val txTotal = AtomicLong(0L)
        val rxTotal = AtomicLong(0L)
        val txInterval = AtomicLong(0L)
        val rxInterval = AtomicLong(0L)
        val connClosedTotal = AtomicInteger(0)
        val connClosedInterval = AtomicInteger(0)
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()

        @Volatile var txIntervalSnap: Long = 0L
        @Volatile var rxIntervalSnap: Long = 0L
        @Volatile var connIntervalSnap: Int = 0
    }

    private val apis = ConcurrentHashMap<String, ApiCounter>()
    private val snapshotLock = Any()

    @Volatile private var paused: Boolean = false

    fun setPaused(p: Boolean) { paused = p }

    /** Build the internal map key. NUL is used as a separator because
     * neither a formatted host nor a URL path can legally contain it. */
    private fun makeKey(host: String, path: String): String = "$host\u0000$path"

    private fun counterFor(host: String, path: String): ApiCounter =
        apis.computeIfAbsent(makeKey(host, path)) { ApiCounter(host, path) }

    /**
     * Add `bytes` of TX (bytes sent to remote) to the counter for the
     * given API endpoint. No-op when paused or when `bytes <= 0`.
     */
    fun addTx(host: String, path: String, bytes: Long) {
        if (paused || bytes <= 0) return
        val c = counterFor(host, path)
        c.txTotal.addAndGet(bytes)
        c.txInterval.addAndGet(bytes)
        c.lastActiveMs = System.currentTimeMillis()
    }

    /** Symmetric to [addTx] for RX bytes. */
    fun addRx(host: String, path: String, bytes: Long) {
        if (paused || bytes <= 0) return
        val c = counterFor(host, path)
        c.rxTotal.addAndGet(bytes)
        c.rxInterval.addAndGet(bytes)
        c.lastActiveMs = System.currentTimeMillis()
    }

    /**
     * Invoked by integration wrappers when one logical flow terminates
     * (an HTTP response drained, a WebSocket closed, a URLConnection
     * stream pair exhausted).
     *
     * @param host              already-formatted endpoint (host[:port]).
     * @param path              normalised URL path.
     * @param txIncrement       bytes tx'd by this flow (can be 0 when the
     *                          caller already reported bytes incrementally).
     * @param rxIncrement       bytes rx'd by this flow.
     * @param flowEndCallback   user callback; receives an [ApiStats] whose
     *                          *Interval fields reflect only THIS flow,
     *                          *Total fields the cumulative current state.
     *                          Safe to pass null. Thrown exceptions are
     *                          swallowed — a buggy host callback MUST NOT
     *                          kill the calling thread (OkHttp dispatcher,
     *                          HTTP transport, ...).
     */
    fun flowEnded(
        host: String,
        path: String,
        txIncrement: Long,
        rxIncrement: Long,
        flowEndCallback: ((ApiStats) -> Unit)?
    ) {
        if (paused) return
        if (txIncrement > 0) addTx(host, path, txIncrement)
        if (rxIncrement > 0) addRx(host, path, rxIncrement)
        val c = counterFor(host, path)
        c.connClosedTotal.incrementAndGet()
        c.connClosedInterval.incrementAndGet()
        c.lastActiveMs = System.currentTimeMillis()
        if (flowEndCallback != null) {
            val snapshot = ApiStats(
                host = host,
                path = path,
                txBytesTotal = c.txTotal.get(),
                rxBytesTotal = c.rxTotal.get(),
                txBytesInterval = txIncrement.coerceAtLeast(0),
                rxBytesInterval = rxIncrement.coerceAtLeast(0),
                connCountTotal = c.connClosedTotal.get(),
                connCountInterval = 1,
                lastActiveMs = c.lastActiveMs
            )
            try {
                flowEndCallback.invoke(snapshot)
            } catch (_: Throwable) {
                // Swallow — see KDoc.
            }
        }
    }

    fun markIntervalBoundary() {
        synchronized(snapshotLock) {
            for (c in apis.values) {
                c.txIntervalSnap = c.txInterval.getAndSet(0L)
                c.rxIntervalSnap = c.rxInterval.getAndSet(0L)
                c.connIntervalSnap = c.connClosedInterval.getAndSet(0)
            }
        }
    }

    fun clear() {
        synchronized(snapshotLock) {
            apis.clear()
        }
    }

    /** Cumulative view — interval fields hold the *live* (unfrozen) current-window bytes. */
    fun getApiStats(): List<ApiStats> {
        return apis.values.map { c ->
            ApiStats(
                host = c.host,
                path = c.path,
                txBytesTotal = c.txTotal.get(),
                rxBytesTotal = c.rxTotal.get(),
                txBytesInterval = c.txInterval.get(),
                rxBytesInterval = c.rxInterval.get(),
                connCountTotal = c.connClosedTotal.get(),
                connCountInterval = c.connClosedInterval.get(),
                lastActiveMs = c.lastActiveMs
            )
        }
    }

    /** Frozen snapshot from the last [markIntervalBoundary]. */
    fun getIntervalStats(): List<ApiStats> {
        return apis.values.map { c ->
            ApiStats(
                host = c.host,
                path = c.path,
                txBytesTotal = c.txTotal.get(),
                rxBytesTotal = c.rxTotal.get(),
                txBytesInterval = c.txIntervalSnap,
                rxBytesInterval = c.rxIntervalSnap,
                connCountTotal = c.connClosedTotal.get(),
                connCountInterval = c.connIntervalSnap,
                lastActiveMs = c.lastActiveMs
            )
        }
    }

    fun getTotalStats(): TotalStats {
        var tx = 0L; var rx = 0L; var cn = 0
        for (c in apis.values) {
            tx += c.txTotal.get()
            rx += c.rxTotal.get()
            cn += c.connClosedTotal.get()
        }
        return TotalStats(txTotal = tx, rxTotal = rx, connCountTotal = cn)
    }
}
