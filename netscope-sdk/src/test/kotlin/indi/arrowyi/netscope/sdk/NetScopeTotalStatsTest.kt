package indi.arrowyi.netscope.sdk

import android.content.Context
import indi.arrowyi.netscope.sdk.internal.SystemTrafficReader
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito

/**
 * v2.0.2 regression tests for the Layer-A [NetScope.getTotalStats] path.
 *
 * The SDK reads kernel-level UID counters via [SystemTrafficReader.DEFAULT].
 * For unit tests we install a [FakeReader] that returns scripted values so
 * we can exercise baseline-subtraction, reboot-wrap, and the UNSUPPORTED
 * fallback deterministically — no device / Robolectric needed.
 */
class NetScopeTotalStatsTest {

    private val context: Context = Mockito.mock(Context::class.java)
    private lateinit var reader: FakeReader

    @Before
    fun setUp() {
        NetScope.destroy()
        NetScope.clearStats()
        reader = FakeReader()
        NetScope.installReaderForTest(reader)
    }

    @After
    fun tearDown() {
        NetScope.destroy()
        NetScope.clearStats()
        NetScope.installReaderForTest(SystemTrafficReader.DEFAULT)
    }

    @Test
    fun `getTotalStats before init returns zeros without touching the reader`() {
        // Reader is set but init() not called. Returns zeros.
        reader.tx = 1_000_000
        reader.rx = 2_000_000
        val out = NetScope.getTotalStats()
        assertEquals(0L, out.txTotal)
        assertEquals(0L, out.rxTotal)
        assertEquals(0, out.connCountTotal)
    }

    @Test
    fun `baseline captured at init, total is current minus baseline`() {
        reader.tx = 1_000
        reader.rx = 5_000
        NetScope.init(context)

        reader.tx = 3_500
        reader.rx = 8_000

        val out = NetScope.getTotalStats()
        assertEquals(2_500L, out.txTotal)
        assertEquals(3_000L, out.rxTotal)
    }

    @Test
    fun `second init is a no-op and baseline is not refreshed`() {
        reader.tx = 100
        reader.rx = 200
        NetScope.init(context)

        reader.tx = 1_100   // 1,000 bytes after init
        reader.rx = 1_200   // 1,000 bytes after init

        // Calling init() again must NOT re-baseline. If it did, the
        // numbers below would be 0 / 0.
        NetScope.init(context)

        val out = NetScope.getTotalStats()
        assertEquals(1_000L, out.txTotal)
        assertEquals(1_000L, out.rxTotal)
    }

    @Test
    fun `UNSUPPORTED reader falls back to AOP aggregator sum`() {
        // Seed the AOP aggregator so the fallback path has something.
        NetScope.reportTx("api.example.com", 123)
        NetScope.reportRx("api.example.com", 456)

        reader.tx = SystemTrafficReader.UNSUPPORTED
        reader.rx = SystemTrafficReader.UNSUPPORTED
        NetScope.init(context)
        // init() clears the aggregator on first call, so re-seed after.
        NetScope.reportTx("api.example.com", 111)
        NetScope.reportRx("api.example.com", 222)

        val out = NetScope.getTotalStats()
        assertEquals("UNSUPPORTED must fall back to AOP sum", 111L, out.txTotal)
        assertEquals("UNSUPPORTED must fall back to AOP sum", 222L, out.rxTotal)
    }

    @Test
    fun `reboot wrap auto-rebaselines to zero`() {
        reader.tx = 1_000_000
        reader.rx = 2_000_000
        NetScope.init(context)

        // Device rebooted mid-session (extremely unlikely: the process
        // would normally die too). Kernel counters went back to 0 + some
        // small post-reboot traffic.
        reader.tx = 500
        reader.rx = 800

        val out = NetScope.getTotalStats()
        // Baseline was silently re-set to 0 (the pre-reboot baseline is
        // greater than the current reading, which is detectable). Total
        // is the post-reboot kernel value.
        assertEquals(500L, out.txTotal)
        assertEquals(800L, out.rxTotal)
    }

    @Test
    fun `init resets per-domain aggregator too`() {
        NetScope.reportTx("a.com", 1_000)
        NetScope.reportRx("b.com", 2_000)
        assertTrue(NetScope.getDomainStats().isNotEmpty())

        NetScope.init(context)
        assertTrue(
            "init() must clear Layer-B per-domain counters",
            NetScope.getDomainStats().isEmpty()
        )
    }

    @Test
    fun `destroy then init re-baselines`() {
        reader.tx = 100
        reader.rx = 200
        NetScope.init(context)

        reader.tx = 500
        reader.rx = 700
        NetScope.destroy()

        // A later session starts with its own baseline.
        reader.tx = 1_000
        reader.rx = 1_500
        NetScope.init(context)

        reader.tx = 1_050
        reader.rx = 1_600

        val out = NetScope.getTotalStats()
        assertEquals(50L, out.txTotal)
        assertEquals(100L, out.rxTotal)
    }

    @Test
    fun `clearStats re-baselines kernel counters as well`() {
        reader.tx = 100
        reader.rx = 200
        NetScope.init(context)

        reader.tx = 5_000
        reader.rx = 6_000
        // Pre-clear, total should be 4,900 / 5,800.
        NetScope.clearStats()

        // Post-clear, total should be 0 / 0 for the same reader value.
        val out = NetScope.getTotalStats()
        assertEquals(0L, out.txTotal)
        assertEquals(0L, out.rxTotal)
    }

    @Test
    fun `pause does not suppress kernel-level totals`() {
        reader.tx = 0
        reader.rx = 0
        NetScope.init(context)

        NetScope.pause()
        reader.tx = 9_000
        reader.rx = 4_000

        val out = NetScope.getTotalStats()
        assertEquals(
            "pause/resume is Layer-B only; Layer-A reflects kernel truth",
            9_000L, out.txTotal
        )
        assertEquals(4_000L, out.rxTotal)
        NetScope.resume()
    }

    @Test
    fun `connCountTotal still reflects AOP-layer flow ends`() {
        reader.tx = 0
        reader.rx = 0
        NetScope.init(context)

        NetScope.aggregator.flowEnded("x.com", 1, 2, null)
        NetScope.aggregator.flowEnded("y.com", 3, 4, null)

        val out = NetScope.getTotalStats()
        assertEquals(
            "connCountTotal stays AOP-based — kernel has no flow concept",
            2, out.connCountTotal
        )
    }

    private class FakeReader : SystemTrafficReader {
        var tx: Long = 0
        var rx: Long = 0
        override fun getUidTxBytes(): Long = tx
        override fun getUidRxBytes(): Long = rx
    }
}
