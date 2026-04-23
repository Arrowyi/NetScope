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

    // ─── Diagnostic mode flags ────────────────────────────────────────────
    //
    // Bitwise OR these into [setDebugMode]. Diagnostic-only: used to
    // pinpoint hard-to-reproduce hooker-conflict crashes on specific OEM
    // devices (e.g. HONOR AGM3-W09HN / Android 10 where asdk.httpclient
    // crashes ~14 s after init). See docs/HOOK_EVOLUTION.md and README
    // "Diagnostic mode" section.
    //
    // NEVER ship with [DEBUG_SKIP_HOOKS] set in production — it disables
    // all traffic collection. [DEBUG_TRACE_HOOKS] is safe to leave on but
    // adds non-trivial logcat volume (~1 line per caller-lib × symbol).

    /** No diagnostics (default). */
    const val DEBUG_NONE: Int = 0

    /**
     * Log every GOT slot NetScope patches:
     *   `bytehook-trace: lib=<caller> sym=<symbol> prev=<old> new=<new>`
     * Warns `CONTESTED` if `prev` doesn't match the dlsym(RTLD_NEXT)-resolved
     * real libc address (i.e. another PLT/GOT hooker got there first).
     *
     * Also turns on bytehook's own debug logs (tag: `bytehook`) and enables
     * `bytehook_set_recordable(true)` so a post-mortem dump is possible.
     */
    const val DEBUG_TRACE_HOOKS: Int = 1 shl 0

    /**
     * Initialise bytehook BUT DO NOT register any of NetScope's stubs.
     * The SDK finishes init in `DEGRADED` state with
     * `failureReason = "diagnostic: DEBUG_SKIP_HOOKS — ..."`.
     *
     * Use to split "does NetScope's hook-install phase cause the crash?"
     * from "does merely loading + initialising bytehook (CFI disable,
     * shadowhook trampolines) cause the crash?". If a crash still occurs
     * with this flag alone, the host app's native stack is incompatible
     * with bytehook in this process — independent of NetScope's writes.
     *
     * Traffic is NOT collected in this mode. DO NOT ship enabled.
     */
    const val DEBUG_SKIP_HOOKS: Int = 1 shl 1

    /**
     * The most aggressive diagnostic: resolve libc via `dlsym(RTLD_NEXT)`
     * and then **stop**. `bytehook_init()` is NEVER called — the
     * shadowhook CFI-disable path, safe-init signal-handler installs,
     * and bytehook's own mmap/mprotect calls are all skipped entirely.
     *
     * If the app still crashes with only this flag set, NetScope's
     * runtime did nothing beyond pure dlsym on libc.so — the trigger
     * must be something that merely *loading* libnetscope.so brings
     * into the process (libbytehook.so DT_NEEDED, static initialisers,
     * etc.). That would be an extremely unusual regression.
     *
     * If the app stops crashing with this flag, the trigger is somewhere
     * inside `bytehook_init`, narrowing the search to that ~100 lines
     * of third-party initialisation code.
     *
     * `HookReport.status = DEGRADED`, `failureReason = "diagnostic:
     * DEBUG_ULTRA_MINIMAL — libc resolved (N/11) but bytehook_init NOT
     * called"`. Traffic is NOT collected.
     *
     * Added 2026-04-23 per HONOR AGM3-W09HN triage, where
     * DEBUG_SKIP_HOOKS still crashed with the same register fingerprint.
     */
    const val DEBUG_ULTRA_MINIMAL: Int = 1 shl 2

    /**
     * Configure diagnostic flags. MUST be called BEFORE [init] — calls
     * after init have no effect. Pass [DEBUG_NONE] in production.
     *
     * Example (a one-shot diagnostic build asking "is the crash caused by
     * NetScope's writes, or by bytehook's init alone?"):
     *
     * ```kotlin
     * NetScope.setDebugMode(NetScope.DEBUG_TRACE_HOOKS or NetScope.DEBUG_SKIP_HOOKS)
     * NetScope.init(context)
     * ```
     */
    fun setDebugMode(flags: Int) {
        NetScopeNative.nativeSetDebugMode(flags)
    }

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
