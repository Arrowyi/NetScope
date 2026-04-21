package com.netscope.sdk

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NetScopeInstrumentedTest {

    // Minimal TLS 1.2 ClientHello with SNI = "api.test.c"
    private val TLS_CLIENT_HELLO = byteArrayOf(
        // TLS record header
        0x16.toByte(),              // content type: Handshake
        0x03, 0x01,                 // legacy record version TLS 1.0
        0x00, 0x3f,                 // record length = 63
        // Handshake header
        0x01,                       // HandshakeType: ClientHello
        0x00, 0x00, 0x3b,           // length = 59
        // ClientHello fields
        0x03, 0x03,                 // client version TLS 1.2
        // Random (32 bytes)
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
        0x00,                       // session ID length = 0
        0x00, 0x02,                 // cipher suites length = 2
        0x00, 0x2f,                 // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,                 // compression: length=1, null
        // Extensions
        0x00, 0x13,                 // extensions total length = 19
        // SNI extension
        0x00, 0x00,                 // extension type = 0 (SNI)
        0x00, 0x0f,                 // extension data length = 15
        0x00, 0x0d,                 // server_name_list length = 13
        0x00,                       // name type = host_name
        0x00, 0x0a,                 // name length = 10
        // "api.test.c"
        0x61, 0x70, 0x69, 0x2e,
        0x74, 0x65, 0x73, 0x74,
        0x2e, 0x63
    )

    @Test
    fun testParseTlsSni() {
        val sni = NetScopeNative.testParseSni(TLS_CLIENT_HELLO)
        assertEquals("api.test.c", sni)
    }

    @Test
    fun testParseTlsSniReturnNullForNonTls() {
        val data = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        val sni = NetScopeNative.testParseSni(data)
        assertNull(sni)
    }

    @Test
    fun testParseHttpHost() {
        val data = "GET / HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n".toByteArray()
        val host = NetScopeNative.testParseHttpHost(data)
        assertEquals("api.example.com", host)
    }

    @Test
    fun testParseHttpHostWithPort() {
        val data = "POST /path HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n".toByteArray()
        val host = NetScopeNative.testParseHttpHost(data)
        assertEquals("api.example.com", host)
    }

    @Test
    fun testDnsCacheStoreAndLookup() {
        System.loadLibrary("netscope")
        NetScopeNative.testDnsCacheStore("192.168.1.1", "api.example.com")
        val domain = NetScopeNative.testDnsCacheLookup("192.168.1.1")
        assertEquals("api.example.com", domain)
    }

    @Test
    fun testDnsCacheMiss() {
        System.loadLibrary("netscope")
        val domain = NetScopeNative.testDnsCacheLookup("10.0.0.99")
        assertNull(domain)
    }

    @Test
    fun testDnsCacheMultipleIps() {
        System.loadLibrary("netscope")
        NetScopeNative.testDnsCacheStore("1.1.1.1", "cdn.example.com")
        NetScopeNative.testDnsCacheStore("1.1.1.2", "cdn.example.com")
        assertEquals("cdn.example.com", NetScopeNative.testDnsCacheLookup("1.1.1.1"))
        assertEquals("cdn.example.com", NetScopeNative.testDnsCacheLookup("1.1.1.2"))
    }
}
