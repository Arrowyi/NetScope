package indi.arrowyi.netscope.sdk.internal

import indi.arrowyi.netscope.sdk.DomainStats
import indi.arrowyi.netscope.sdk.TotalStats
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * In-process per-domain traffic counters.
 *
 * Concurrency model:
 *  - Every domain has its own [DomainCounter] holding AtomicLong counters
 *    for tx/rx (cumulative and current-interval) and an AtomicInteger for
 *    closed-flow count. All increments are lock-free.
 *  - The domain map is a [ConcurrentHashMap]; `computeIfAbsent` is used
 *    to install new counters atomically.
 *  - Interval boundaries are taken under [snapshotLock] to make
 *    "snapshot the interval and reset interval counters" one atomic step
 *    relative to readers of [getIntervalStats]. Writers (addTx/addRx) do
 *    NOT take this lock — they atomically add to both cumulative and
 *    interval counters; a boundary that races with an addTx may attribute
 *    the bytes to the new interval. Over long time scales this is a
 *    rounding error, not a correctness issue.
 */
internal class TrafficAggregator {

    private class DomainCounter(val domain: String) {
        val txTotal = AtomicLong(0L)
        val rxTotal = AtomicLong(0L)
        val txInterval = AtomicLong(0L)
        val rxInterval = AtomicLong(0L)
        val connClosedTotal = AtomicInteger(0)
        val connClosedInterval = AtomicInteger(0)
        @Volatile var lastActiveMs: Long = System.currentTimeMillis()

        // last-snapshot values — what the most recent markIntervalBoundary
        // froze, returned by getIntervalStats(). We keep them frozen so
        // repeated reads between boundaries are stable and cheap.
        @Volatile var txIntervalSnap: Long = 0L
        @Volatile var rxIntervalSnap: Long = 0L
        @Volatile var connIntervalSnap: Int = 0
    }

    private val domains = ConcurrentHashMap<String, DomainCounter>()
    private val snapshotLock = Any()

    @Volatile private var paused: Boolean = false

    fun setPaused(p: Boolean) { paused = p }

    private fun counterFor(domain: String): DomainCounter =
        domains.computeIfAbsent(domain) { DomainCounter(it) }

    /**
     * Called by the integration wrappers (interceptor / URL connection /
     * WebSocket) as soon as bytes are observed. [flowEndCallback], set
     * via [setOnFlowEnd], does NOT fire from here — it fires on
     * [flowEnded].
     */
    fun addTx(domain: String, bytes: Long) {
        if (paused || bytes <= 0) return
        val c = counterFor(domain)
        c.txTotal.addAndGet(bytes)
        c.txInterval.addAndGet(bytes)
        c.lastActiveMs = System.currentTimeMillis()
    }

    fun addRx(domain: String, bytes: Long) {
        if (paused || bytes <= 0) return
        val c = counterFor(domain)
        c.rxTotal.addAndGet(bytes)
        c.rxInterval.addAndGet(bytes)
        c.lastActiveMs = System.currentTimeMillis()
    }

    /**
     * Invoked by integration wrappers when one logical flow
     * (HTTP request/response cycle, a closed WebSocket, a closed
     * HttpsURLConnection stream pair, ...) terminates.
     *
     * @param domain            host the flow targeted
     * @param txIncrement       bytes tx'd by this flow (can be 0; many
     *                          callers already called addTx incrementally)
     * @param rxIncrement       bytes rx'd by this flow
     * @param flowEndCallback   user-supplied callback, invoked with a
     *                          DomainStats whose *Interval fields reflect
     *                          only THIS flow. Safe to pass null.
     */
    fun flowEnded(
        domain: String,
        txIncrement: Long,
        rxIncrement: Long,
        flowEndCallback: ((DomainStats) -> Unit)?
    ) {
        if (paused) return
        if (txIncrement > 0) addTx(domain, txIncrement)
        if (rxIncrement > 0) addRx(domain, rxIncrement)
        val c = counterFor(domain)
        c.connClosedTotal.incrementAndGet()
        c.connClosedInterval.incrementAndGet()
        c.lastActiveMs = System.currentTimeMillis()
        if (flowEndCallback != null) {
            // Construct a per-flow DomainStats — Interval fields hold
            // exactly the flow's own bytes, Total fields reflect the
            // current cumulative state.
            val snapshot = DomainStats(
                domain = domain,
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
                // A buggy host callback MUST NOT kill the calling thread
                // (HTTP transport, OkHttp dispatcher, ...). Swallow silently.
            }
        }
    }

    fun markIntervalBoundary() {
        synchronized(snapshotLock) {
            for (c in domains.values) {
                c.txIntervalSnap = c.txInterval.getAndSet(0L)
                c.rxIntervalSnap = c.rxInterval.getAndSet(0L)
                c.connIntervalSnap = c.connClosedInterval.getAndSet(0)
            }
        }
    }

    fun clear() {
        synchronized(snapshotLock) {
            domains.clear()
        }
    }

    fun getDomainStats(): List<DomainStats> {
        return domains.values.map { c ->
            DomainStats(
                domain = c.domain,
                txBytesTotal = c.txTotal.get(),
                rxBytesTotal = c.rxTotal.get(),
                // "current" interval fields for cumulative API = live values
                txBytesInterval = c.txInterval.get(),
                rxBytesInterval = c.rxInterval.get(),
                connCountTotal = c.connClosedTotal.get(),
                connCountInterval = c.connClosedInterval.get(),
                lastActiveMs = c.lastActiveMs
            )
        }
    }

    fun getIntervalStats(): List<DomainStats> {
        // Return the frozen snapshot from the last markIntervalBoundary.
        return domains.values.map { c ->
            DomainStats(
                domain = c.domain,
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
        for (c in domains.values) {
            tx += c.txTotal.get()
            rx += c.rxTotal.get()
            cn += c.connClosedTotal.get()
        }
        return TotalStats(txTotal = tx, rxTotal = rx, connCountTotal = cn)
    }
}
