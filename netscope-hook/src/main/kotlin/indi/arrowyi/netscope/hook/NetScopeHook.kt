package indi.arrowyi.netscope.hook

import android.content.Context
import android.util.Log

/**
 * Optional Layer D — socket-level traffic tracking via PLT hooks.
 *
 * This module intercepts `connect/send/recv/write/read/close` in libc
 * through a self-contained PLT patcher (`libnetscope_hook.so`) that:
 *   - contains NO third-party hook libraries (no shadowhook, no bytehook),
 *   - uses only GOT patching (no mmap(PROT_EXEC)) so it is safe on W^X
 *     kernels (IVI / OEM head-units).
 *
 * **Layer relationships:**
 * ```
 *   sum(getSocketStats().txBytes)  ≈  NetScope.getTotalStats().txTotal  (Layer A)
 *   sum(getSocketStats().txBytes)  ≈  sum(NetScope.getApiStats().txBytesTotal)   // Layer B
 *                                   + sum(NetScope.getCppApiStats().txBytes)      // Layer C
 *                                   + unattributed gap
 * ```
 *
 * **Usage:**
 * ```kotlin
 * NetScope.init(context)      // Layer A + B + C
 * NetScopeHook.init(context)  // Layer D — optional; safe to skip
 * NetScopeHook.start()        // install PLT hooks
 * // ... traffic flows ...
 * val sockets = NetScopeHook.getSocketStats()
 * val total   = NetScopeHook.getSocketTotalStats()
 * NetScopeHook.stop()
 * ```
 *
 * **Risk / kill-switch:** if stability issues appear on a specific device,
 * simply don't call [init] or [start]. `libnetscope_hook.so` is never in the
 * `DT_NEEDED` of any other library — it exists only when this module is
 * included as a dependency and [init] is called.
 */
object NetScopeHook {

    private const val TAG = "NetScopeHook"
    private const val LIB_NAME = "netscope_hook"

    @Volatile private var libLoaded: Boolean = false
    @Volatile private var active: Boolean = false

    /**
     * Load `libnetscope_hook.so`. Idempotent; silently no-ops if the library
     * fails to load (e.g. device not supported). Must be called before [start].
     */
    fun init(@Suppress("UNUSED_PARAMETER") context: Context) {
        if (libLoaded) return
        try {
            System.loadLibrary(LIB_NAME)
            libLoaded = true
            Log.i(TAG, "libnetscope_hook loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Failed to load libnetscope_hook — Layer D inactive: ${e.message}")
        }
    }

    /**
     * Install PLT hooks. Returns `true` if hooks were installed successfully,
     * `false` if [init] was not called or the native install failed.
     *
     * Hooks are re-entrant-safe and will no-op when called from within a
     * hooked function.
     */
    fun start(): Boolean {
        if (!libLoaded) {
            Log.w(TAG, "start() called before init() — Layer D inactive")
            return false
        }
        return try {
            val ok = nativeStart()
            active = ok
            if (ok) Log.i(TAG, "PLT hooks installed") else Log.w(TAG, "nativeStart() returned false")
            ok
        } catch (e: Throwable) {
            Log.e(TAG, "start() threw: ${e.message}")
            false
        }
    }

    /**
     * Uninstall PLT hooks (restore original GOT entries). Safe to call even
     * if [start] was never called.
     */
    fun stop() {
        if (!libLoaded) return
        try {
            nativeStop()
            active = false
            Log.i(TAG, "PLT hooks removed")
        } catch (e: Throwable) {
            Log.e(TAG, "stop() threw: ${e.message}")
        }
    }

    /** Whether PLT hooks are currently installed. */
    val isActive: Boolean get() = active

    /**
     * Cumulative per-endpoint stats from the socket hook (Layer D).
     *
     * Each entry is one remote `"ip:port"` observed since the last
     * [clearSocketStats] (or since [start]). Only connections that have been
     * `close()`d appear here; in-flight connections are not yet reported.
     *
     * Sorted by total bytes descending.
     */
    fun getSocketStats(): List<SocketStats> {
        if (!libLoaded) return emptyList()
        return try {
            nativeGetSocketStats()?.sortedByDescending { it.totalBytes } ?: emptyList()
        } catch (e: Throwable) {
            Log.e(TAG, "getSocketStats() threw: ${e.message}")
            emptyList()
        }
    }

    /**
     * Aggregate total bytes and connection count across all tracked sockets.
     * Returns zeros if [init] was not called.
     */
    fun getSocketTotalStats(): SocketTotalStats {
        if (!libLoaded) return SocketTotalStats(0L, 0L, 0)
        return try {
            nativeGetSocketTotalStats() ?: SocketTotalStats(0L, 0L, 0)
        } catch (e: Throwable) {
            Log.e(TAG, "getSocketTotalStats() threw: ${e.message}")
            SocketTotalStats(0L, 0L, 0)
        }
    }

    /**
     * Clear all accumulated socket stats. Does not stop the hook — new
     * stats will accumulate from this point forward.
     */
    fun clearSocketStats() {
        if (!libLoaded) return
        try { nativeClearStats() } catch (_: Throwable) {}
    }

    // ─── JNI declarations ────────────────────────────────────────────────────

    private external fun nativeStart(): Boolean
    private external fun nativeStop()
    private external fun nativeGetSocketStats(): List<SocketStats>?
    private external fun nativeGetSocketTotalStats(): SocketTotalStats?
    private external fun nativeClearStats()
}
