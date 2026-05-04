package indi.arrowyi.netscope.sdk

import indi.arrowyi.netscope.sdk.internal.CppTrafficAggregator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CppTrafficAggregatorTest {

    @Test fun aggregatesPerHostAndPath() {
        val agg = CppTrafficAggregator()
        agg.report("api.example.com", "/v1/route", 1024, 4096, 150.0)
        agg.report("api.example.com", "/v1/route", 512, 2048, 80.0)
        agg.report("api.example.com", "/v1/tiles", 256, 512, 30.0)

        val stats = agg.getCppApiStats().associateBy { it.key }
        val route = stats.getValue("api.example.com/v1/route")
        assertEquals(1024 + 512L, route.txBytes)
        assertEquals(4096 + 2048L, route.rxBytes)
        assertEquals(2, route.requestCount)
        assertEquals(150.0 + 80.0, route.totalTransferTimeMs, 1.0)

        val tiles = stats.getValue("api.example.com/v1/tiles")
        assertEquals(256L, tiles.txBytes)
        assertEquals(1, tiles.requestCount)
    }

    @Test fun differentHostsAreDistinctEntries() {
        val agg = CppTrafficAggregator()
        agg.report("a.com", "/api", 100, 200, 10.0)
        agg.report("b.com", "/api", 300, 400, 20.0)

        val stats = agg.getCppApiStats().associateBy { it.key }
        assertEquals(2, stats.size)
        assertTrue(stats.containsKey("a.com/api"))
        assertTrue(stats.containsKey("b.com/api"))
    }

    @Test fun clearResetsAllCounters() {
        val agg = CppTrafficAggregator()
        agg.report("a.com", "/x", 100, 200, 50.0)
        agg.clear()
        assertTrue(agg.getCppApiStats().isEmpty())
    }

    @Test fun zeroOrNegativeBytesIgnored() {
        val agg = CppTrafficAggregator()
        agg.report("a.com", "/x", 0, -5, 10.0)
        val stats = agg.getCppApiStats().firstOrNull()
        // Entry should exist (requestCount=1) but bytes should be 0.
        assertEquals(1, stats?.requestCount ?: 0)
        assertEquals(0L, stats?.txBytes ?: 0L)
        assertEquals(0L, stats?.rxBytes ?: 0L)
    }
}
