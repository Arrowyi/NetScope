package indi.arrowyi.netscope.sdk

internal object NetScopeNative {
    init { System.loadLibrary("netscope") }

    external fun nativeInit(): Int        // returns 0 on success
    external fun nativeDestroy()
    external fun nativePause()
    external fun nativeResume()
    external fun nativeClearStats()
    external fun nativeMarkIntervalBoundary()
    external fun nativeGetDomainStats(): Array<DomainStats>
    external fun nativeGetIntervalStats(): Array<DomainStats>
    external fun nativeSetFlowEndCallback(callback: ((DomainStats) -> Unit)?)

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
