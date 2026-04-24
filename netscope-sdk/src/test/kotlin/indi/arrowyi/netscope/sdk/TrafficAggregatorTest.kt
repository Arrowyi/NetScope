package indi.arrowyi.netscope.sdk

import indi.arrowyi.netscope.sdk.internal.TrafficAggregator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit-level smoke tests for the pure-Kotlin aggregator. No Android
 * classes, no OkHttp, no network — we only verify that the counting
 * semantics advertised in [NetScope]'s KDoc hold.
 */
class TrafficAggregatorTest {

    @Test fun addsBytesPerDomain() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", 100)
        agg.addRx("a.com", 300)
        agg.addTx("b.com", 50)

        val stats = agg.getDomainStats().associateBy { it.domain }
        assertEquals(100L, stats.getValue("a.com").txBytesTotal)
        assertEquals(300L, stats.getValue("a.com").rxBytesTotal)
        assertEquals(50L,  stats.getValue("b.com").txBytesTotal)
    }

    @Test fun totalStatsSumsAcrossDomains() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", 10); agg.addRx("a.com", 20)
        agg.addTx("b.com", 30); agg.addRx("b.com", 40)

        val total = agg.getTotalStats()
        assertEquals(40L, total.txTotal)
        assertEquals(60L, total.rxTotal)
    }

    @Test fun pauseSuppressesIncrements() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", 10)
        agg.setPaused(true)
        agg.addTx("a.com", 999)
        agg.addRx("a.com", 999)
        agg.setPaused(false)
        agg.addTx("a.com", 1)

        val row = agg.getDomainStats().single()
        assertEquals(11L, row.txBytesTotal)
        assertEquals(0L,  row.rxBytesTotal)
    }

    @Test fun intervalBoundaryFreezesSnapshot() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", 10)
        agg.addRx("a.com", 20)
        agg.markIntervalBoundary()
        // Frozen snapshot preserves pre-boundary bytes.
        val afterBoundary = agg.getIntervalStats().single()
        assertEquals(10L, afterBoundary.txBytesInterval)
        assertEquals(20L, afterBoundary.rxBytesInterval)

        // New activity doesn't change the frozen snapshot until the next boundary.
        agg.addTx("a.com", 5)
        val stillFrozen = agg.getIntervalStats().single()
        assertEquals(10L, stillFrozen.txBytesInterval)

        agg.markIntervalBoundary()
        val nextInterval = agg.getIntervalStats().single()
        assertEquals(5L, nextInterval.txBytesInterval)
    }

    @Test fun flowEndedIncrementsConnCountAndInvokesCallback() {
        val agg = TrafficAggregator()
        val received = mutableListOf<DomainStats>()

        agg.flowEnded("a.com", txIncrement = 100, rxIncrement = 200) { received.add(it) }

        val row = agg.getDomainStats().single()
        assertEquals(100L, row.txBytesTotal)
        assertEquals(200L, row.rxBytesTotal)
        assertEquals(1, row.connCountTotal)

        assertEquals(1, received.size)
        val cb = received.first()
        assertEquals("a.com", cb.domain)
        assertEquals(100L, cb.txBytesInterval)
        assertEquals(200L, cb.rxBytesInterval)
        assertEquals(1, cb.connCountInterval)
    }

    @Test fun clearResetsCounters() {
        val agg = TrafficAggregator()
        agg.addTx("a.com", 10)
        agg.addRx("b.com", 20)
        agg.clear()
        assertTrue(agg.getDomainStats().isEmpty())
        assertEquals(0L, agg.getTotalStats().txTotal)
    }
}
