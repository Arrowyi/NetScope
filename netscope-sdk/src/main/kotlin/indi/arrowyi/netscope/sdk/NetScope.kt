package indi.arrowyi.netscope.sdk

import android.content.Context
import android.util.Log

/**
 * Entry point for NetScope network traffic monitoring SDK.
 *
 * Call [init] once in your Application.onCreate(). The SDK installs PLT hooks into
 * the current process and begins tracking all TCP connections and their byte counts,
 * attributing traffic to domain names via TLS SNI, HTTP Host header, and DNS cache.
 */
object NetScope {

    private const val TAG = "NetScope"
    private var initialized = false

    /**
     * Load native library, install PLT hooks, start collecting statistics.
     * Safe to call multiple times — subsequent calls are no-ops.
     *
     * @return the SDK's [Status] after this call. Callers should check
     *   against [Status.ACTIVE] / [Status.DEGRADED] / [Status.FAILED] and
     *   surface the result in any diagnostic UI (HMI, overlay, etc.).
     *   [getHookReport] returns the full detail.
     */
    @Synchronized
    fun init(context: Context): Status {
        if (initialized) return getHookReport().status
        val ret = NetScopeNative.nativeInit()
        val report = getHookReport()
        if (ret != 0 || report.status == Status.FAILED) {
            Log.e(TAG, "Native init failed: ret=$ret status=${report.status} reason=${report.failureReason}")
            initialized = (report.status != Status.FAILED)
            return report.status
        }
        initialized = true
        if (report.status == Status.DEGRADED) {
            Log.w(TAG, "Initialized in DEGRADED state: ${report.failureReason}")
        } else {
            Log.i(TAG, "Initialized, status=${report.status}")
        }
        return report.status
    }

    /**
     * Current hook health snapshot. Safe to call from any thread and at any
     * time — returns NOT_INITIALIZED before [init] has run.
     */
    fun getHookReport(): HookReport = NetScopeNative.nativeGetHookReport()

    /**
     * Register a listener invoked whenever the SDK's overall [Status] changes.
     *
     * Typical use: show/hide an HMI indicator like "traffic monitor running"
     * based on [HookReport.isCollecting]. The callback may be invoked on any
     * thread (the one that triggered the transition — usually the init caller
     * or the dlopen path that hit a bad library). Dispatch to the UI thread
     * yourself if needed.
     *
     * Pass `null` to clear.
     */
    fun setStatusListener(callback: ((HookReport) -> Unit)?) {
        NetScopeNative.nativeSetStatusListener(callback)
    }

    /** Pause stats collection. PLT hooks remain installed; bytes are not counted. */
    fun pause() = NetScopeNative.nativePause()

    /** Resume stats collection after [pause]. */
    fun resume() = NetScopeNative.nativeResume()

    /**
     * Uninstall all PLT hooks and release native resources.
     * Typically not needed — only call when you want to completely remove the SDK.
     */
    @Synchronized
    fun destroy() {
        NetScopeNative.nativeDestroy()
        LogcatReporter.stop()
        initialized = false
    }

    /** Reset all collected statistics. Hooks are unaffected. */
    fun clearStats() = NetScopeNative.nativeClearStats()

    /**
     * Mark the end of the current interval window.
     * After this call, [getIntervalStats] returns the just-completed window's data,
     * and a new window begins. Called automatically by [setLogInterval].
     */
    fun markIntervalBoundary() = NetScopeNative.nativeMarkIntervalBoundary()

    /**
     * Return cumulative domain statistics since [init] or last [clearStats],
     * sorted by total traffic descending.
     */
    fun getDomainStats(): List<DomainStats> =
        NetScopeNative.nativeGetDomainStats().sortedByDescending { it.totalBytes }

    /**
     * Return statistics for the last completed interval window,
     * sorted by interval traffic descending.
     */
    fun getIntervalStats(): List<DomainStats> =
        NetScopeNative.nativeGetIntervalStats()
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }

    /**
     * Enable automatic Logcat output every [seconds] seconds (Tag: NetScope).
     * Each print also calls [markIntervalBoundary].
     * Pass 0 to disable.
     */
    fun setLogInterval(seconds: Int) {
        if (seconds > 0) LogcatReporter.start(seconds) else LogcatReporter.stop()
    }

    /**
     * Register a callback invoked on the reporting thread each time a connection closes.
     * The [DomainStats] parameter's txBytesInterval/rxBytesInterval reflect the delta
     * for that single connection. Keep the callback lightweight.
     */
    fun setOnFlowEnd(callback: ((DomainStats) -> Unit)?) {
        NetScopeNative.nativeSetFlowEndCallback(callback)
    }
}
