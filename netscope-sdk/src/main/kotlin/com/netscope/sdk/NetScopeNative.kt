package com.netscope.sdk

internal object NetScopeNative {
    init { System.loadLibrary("netscope") }

    external fun nativeInit(): Int

    // Test helpers
    external fun testParseSni(buf: ByteArray): String?
    external fun testParseHttpHost(buf: ByteArray): String?
    external fun testDnsCacheStore(ip: String, domain: String)
    external fun testDnsCacheLookup(ip: String): String?
}
