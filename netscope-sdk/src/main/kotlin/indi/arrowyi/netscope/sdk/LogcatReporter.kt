package indi.arrowyi.netscope.sdk

import android.util.Log
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

internal object LogcatReporter {
    private const val TAG = "NetScope"
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "NetScope-LogcatReporter").also { it.isDaemon = true }
    }
    private var future: ScheduledFuture<*>? = null
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    fun start(intervalSeconds: Int) {
        stop()
        if (intervalSeconds <= 0) return
        future = scheduler.scheduleAtFixedRate({
            runCatching { printReport() }.onFailure {
                Log.w(TAG, "periodic report failed: ${it.message}")
            }
        }, intervalSeconds.toLong(), intervalSeconds.toLong(), TimeUnit.SECONDS)
    }

    fun stop() {
        future?.cancel(false)
        future = null
    }

    private fun printReport() {
        NetScope.markIntervalBoundary()
        val rawInterval = NetScope.getIntervalStats()
        val rawCumulative = NetScope.getApiStats()
        val total = NetScope.getTotalStats()
        val interval = rawInterval
            .filter { it.txBytesInterval + it.rxBytesInterval > 0 }
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }

        val ts = dateFmt.format(Date())
        Log.d(TAG, "report raw interval=${rawInterval.size} cumulative=${rawCumulative.size}")
        Log.i(TAG, "══════ Traffic Report [$ts] ══════")
        Log.i(TAG, "── Interval ──────────────────────────────")
        interval.forEach { s ->
            Log.i(TAG, "  %-60s ↑%-10s ↓%-10s conn=%d".format(
                s.key, fmtBytes(s.txBytesInterval), fmtBytes(s.rxBytesInterval), s.connCountInterval))
        }
        Log.i(TAG, "── Cumulative ────────────────────────────")
        rawCumulative.forEach { s ->
            Log.i(TAG, "  %-60s ↑%-10s ↓%-10s conn=%d".format(
                s.key, fmtBytes(s.txBytesTotal), fmtBytes(s.rxBytesTotal), s.connCountTotal))
        }
        Log.i(TAG, "── Total (kernel UID, since init) ────────")
        Log.i(TAG, "  ↑%s  ↓%s  conn=%d".format(
            fmtBytes(total.txTotal), fmtBytes(total.rxTotal), total.connCountTotal))
        val attributed = rawCumulative.sumOf { it.txBytesTotal + it.rxBytesTotal }
        val unattributed = (total.txTotal + total.rxTotal) - attributed
        if (unattributed > 0) {
            Log.i(TAG, "  non-instrumented (native/NDK): %s".format(fmtBytes(unattributed)))
        }
        Log.i(TAG, "═════════════════════════════════════════")
    }

    private fun fmtBytes(bytes: Long): String = when {
        bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024     -> "%.1f KB".format(bytes / 1_024.0)
        else               -> "$bytes B"
    }
}
