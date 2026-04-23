package indi.arrowyi.netscope.sdk

internal object NetScopeNative {
    init {
        // Load bytehook FIRST. libnetscope.so has a DT_NEEDED on libbytehook.so
        // (provided by the com.bytedance:bytehook Gradle dependency). If we
        // don't pre-load it, Android's runtime loader still finds it — but
        // pre-loading surfaces a clearer UnsatisfiedLinkError if the app
        // forgot to include bytehook.
        try {
            System.loadLibrary("bytehook")
        } catch (t: Throwable) {
            // Don't hard-fail: let the libnetscope load below produce the
            // authoritative error. But log the cause for debugging.
            android.util.Log.e(
                "NetScope",
                "loadLibrary(bytehook) failed; check that the consuming app " +
                "depends (transitively) on com.bytedance:bytehook:1.1.1 — $t"
            )
        }
        System.loadLibrary("netscope")
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
