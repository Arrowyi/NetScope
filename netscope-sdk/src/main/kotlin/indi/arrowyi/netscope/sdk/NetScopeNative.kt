package indi.arrowyi.netscope.sdk

internal object NetScopeNative {
    init {
        // IMPORTANT — we deliberately do NOT `System.loadLibrary("bytehook")`
        // here. libnetscope.so no longer lists libbytehook.so in DT_NEEDED
        // (see netscope-sdk/src/main/cpp/CMakeLists.txt); the native side
        // dlopen's libbytehook.so on demand via hook/bytehook_runtime.cpp.
        // Pre-loading bytehook here would defeat that defer-loading design
        // on the HONOR AGM3-W09HN / EMUI 11 class of devices where
        // bytehook/shadowhook's static constructors destabilise the host
        // process at load time. See docs/HOOK_EVOLUTION.md 2026-04-23 entry.
        //
        // NetScope.init() is responsible for calling
        // NetScope.ensureBytehookLoaded() at the appropriate moment — i.e.
        // only when the caller actually wants hooks installed (not in
        // DEBUG_ULTRA_MINIMAL mode).
        System.loadLibrary("netscope")
    }

    /**
     * Load libbytehook.so on demand. Returns `true` on success. Catches
     * UnsatisfiedLinkError so the hook manager can surface a structured
     * FAILED status instead of crashing the host app. Safe to call from
     * any thread; [System.loadLibrary] is itself synchronised.
     */
    internal fun tryLoadBytehook(): Boolean {
        return try {
            System.loadLibrary("bytehook")
            true
        } catch (t: Throwable) {
            android.util.Log.e(
                "NetScope",
                "loadLibrary(bytehook) failed; host app must depend on " +
                "com.bytedance:bytehook:1.1.1 (as api or implementation) — $t"
            )
            false
        }
    }

    external fun nativeInit(): Int        // returns 0 on ACTIVE / DEGRADED, non-zero on FAILED
    external fun nativeSetDebugMode(flags: Int)    // call BEFORE nativeInit; see NetScope.setDebugMode
    external fun nativeDestroy()
    external fun nativePause()
    external fun nativeResume()
    external fun nativeClearStats()
    external fun nativeMarkIntervalBoundary()
    external fun nativeGetDomainStats(): Array<DomainStats>
    external fun nativeGetIntervalStats(): Array<DomainStats>
    external fun nativeSetFlowEndCallback(callback: ((DomainStats) -> Unit)?)

    // Hook health / status — see HookReport.kt
    external fun nativeGetHookReport(): HookReport
    external fun nativeSetStatusListener(callback: ((HookReport) -> Unit)?)

    // Test helpers
    external fun testParseSni(buf: ByteArray): String?
    external fun testParseHttpHost(buf: ByteArray): String?
    external fun testDnsCacheStore(ip: String, domain: String)
    external fun testDnsCacheLookup(ip: String): String?
    external fun testFlowCreate(fd: Int, ip: String, port: Int, domain: String)
    external fun testFlowAddTx(fd: Int, bytes: Long)
    external fun testFlowAddRx(fd: Int, bytes: Long)
    external fun testFlowGetDomain(fd: Int): String?
    external fun testFlowGetTx(fd: Int): Long
    external fun testFlowGetRx(fd: Int): Long
    external fun testStatsClear()
    external fun testStatsFlush(domain: String, tx: Long, rx: Long)
    external fun testStatsMark()
    external fun testStatsGetCumulative(): Array<String>
    external fun testStatsGetInterval(): Array<String>
}
