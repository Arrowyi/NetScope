package com.netscope.sdk

internal object NetScopeNative {
    init { System.loadLibrary("netscope") }

    external fun nativeInit(): Int

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
}
