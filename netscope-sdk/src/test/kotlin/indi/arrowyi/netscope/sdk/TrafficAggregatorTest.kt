package indi.arrowyi.netscope.sdk

import indi.arrowyi.netscope.sdk.internal.TrafficAggregator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit-level smoke tests for the pure-Kotlin aggregator. No Android
 * classes, no OkHttp, no network — we only verify that the counting
 * semantics advertised in [NetScope]'s KDoc hold.
 *
 * v3.0.0: aggregator keys on `(host, path)`, exposes [ApiStats] rather
 * than `DomainStats`.
 */
class TrafficAggregatorTest {

    @Test fun addsBytesPerApi() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/v1/users", 100)
        agg.addRx("a.com", "/v1/users", 300)
        agg.addTx("a.com", "/v1/orders", 50)
        agg.addTx("b.com", "/ping", 25)

        val stats = agg.getApiStats().associateBy { it.key }
        assertEquals(100L, stats.getValue("a.com/v1/users").txBytesTotal)
        assertEquals(300L, stats.getValue("a.com/v1/users").rxBytesTotal)
        assertEquals(50L,  stats.getValue("a.com/v1/orders").txBytesTotal)
        assertEquals(25L,  stats.getValue("b.com/ping").txBytesTotal)
    }

    @Test fun sameHostDifferentPathAreDistinctEntries() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/v1/users", 1)
        agg.addTx("a.com", "/v1/orders", 1)
        val entries = agg.getApiStats().map { it.key }.toSet()
        assertTrue("/v1/users" in entries.joinToString())
        assertEquals(setOf("a.com/v1/users", "a.com/v1/orders"), entries)
    }

    @Test fun hostWithPortIsKeptVerbatim() {
        val agg = TrafficAggregator()
        agg.addTx("192.168.1.5:9000", "/api/echo", 10)
        agg.addTx("192.168.1.5", "/api/echo", 20)

        val stats = agg.getApiStats().associateBy { it.key }
        assertEquals(
            "`:9000` variant must be a separate API key from the default-port variant",
            10L, stats.getValue("192.168.1.5:9000/api/echo").txBytesTotal
        )
        assertEquals(20L, stats.getValue("192.168.1.5/api/echo").txBytesTotal)
    }

    @Test fun totalStatsSumsAcrossApis() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/x", 10); agg.addRx("a.com", "/x", 20)
        agg.addTx("b.com", "/y", 30); agg.addRx("b.com", "/y", 40)

        val total = agg.getTotalStats()
        assertEquals(40L, total.txTotal)
        assertEquals(60L, total.rxTotal)
    }

    @Test fun pauseSuppressesIncrements() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/x", 10)
        agg.setPaused(true)
        agg.addTx("a.com", "/x", 999)
        agg.addRx("a.com", "/x", 999)
        agg.setPaused(false)
        agg.addTx("a.com", "/x", 1)

        val row = agg.getApiStats().single()
        assertEquals(11L, row.txBytesTotal)
        assertEquals(0L,  row.rxBytesTotal)
    }

    @Test fun intervalBoundaryFreezesSnapshot() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/x", 10)
        agg.addRx("a.com", "/x", 20)
        agg.markIntervalBoundary()
        // Frozen snapshot preserves pre-boundary bytes.
        val afterBoundary = agg.getIntervalStats().single()
        assertEquals(10L, afterBoundary.txBytesInterval)
        assertEquals(20L, afterBoundary.rxBytesInterval)

        // New activity doesn't change the frozen snapshot until the next boundary.
        agg.addTx("a.com", "/x", 5)
        val stillFrozen = agg.getIntervalStats().single()
        assertEquals(10L, stillFrozen.txBytesInterval)

        agg.markIntervalBoundary()
        val nextInterval = agg.getIntervalStats().single()
        assertEquals(5L, nextInterval.txBytesInterval)
    }

    @Test fun flowEndedIncrementsConnCountAndInvokesCallback() {
        val agg = TrafficAggregator()
        val received = mutableListOf<ApiStats>()

        agg.flowEnded("a.com", "/v1/users", txIncrement = 100, rxIncrement = 200) {
            received.add(it)
        }

        val row = agg.getApiStats().single()
        assertEquals(100L, row.txBytesTotal)
        assertEquals(200L, row.rxBytesTotal)
        assertEquals(1, row.connCountTotal)

        assertEquals(1, received.size)
        val cb = received.first()
        assertEquals("a.com", cb.host)
        assertEquals("/v1/users", cb.path)
        assertEquals("a.com/v1/users", cb.key)
        assertEquals(100L, cb.txBytesInterval)
        assertEquals(200L, cb.rxBytesInterval)
        assertEquals(1, cb.connCountInterval)
    }

    @Test fun clearResetsCounters() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", "/x", 10)
        agg.addRx("b.com", "/y", 20)
        agg.clear()
        assertTrue(agg.getApiStats().isEmpty())
        assertEquals(0L, agg.getTotalStats().txTotal)
    }

    @Test fun swallowsExceptionsThrownFromFlowCallback() {
        val agg = TrafficAggregator()
        // A buggy host callback must not propagate through flowEnded;
        // the transport thread that's wiring up close() on a URLConnection
        // cannot afford to die from a host-side log line typo.
        agg.flowEnded("a.com", "/x", 1, 1) { throw RuntimeException("boom") }
        assertNotNull(agg.getApiStats().singleOrNull())
    }
}
