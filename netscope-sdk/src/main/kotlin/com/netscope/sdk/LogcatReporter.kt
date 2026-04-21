package com.netscope.sdk

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
            printReport()
        }, intervalSeconds.toLong(), intervalSeconds.toLong(), TimeUnit.SECONDS)
    }

    fun stop() {
        future?.cancel(false)
        future = null
    }

    private fun printReport() {
        NetScopeNative.nativeMarkIntervalBoundary()
        val interval = NetScopeNative.nativeGetIntervalStats()
            .filter { it.txBytesInterval + it.rxBytesInterval > 0 }
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }
        val cumulative = NetScopeNative.nativeGetDomainStats()
            .sortedByDescending { it.totalBytes }

        val ts = dateFmt.format(Date())
        Log.i(TAG, "══════ Traffic Report [$ts] ══════")
        Log.i(TAG, "── Interval ──────────────────────────────")
        interval.forEach { s ->
            Log.i(TAG, "  %-40s ↑%-10s ↓%-10s conn=%d".format(
                s.domain, fmtBytes(s.txBytesInterval), fmtBytes(s.rxBytesInterval), s.connCountInterval))
        }
        Log.i(TAG, "── Cumulative ────────────────────────────")
        cumulative.forEach { s ->
            Log.i(TAG, "  %-40s ↑%-10s ↓%-10s conn=%d".format(
                s.domain, fmtBytes(s.txBytesTotal), fmtBytes(s.rxBytesTotal), s.connCountTotal))
        }
        Log.i(TAG, "═════════════════════════════════════════")
    }

    private fun fmtBytes(bytes: Long): String = when {
        bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024     -> "%.1f KB".format(bytes / 1_024.0)
        else               -> "$bytes B"
    }
}
