package indi.arrowyi.netscope.sdk.internal

import org.junit.Assert.assertEquals
import org.junit.Test

class EndpointFormatterTest {

    @Test
    fun `default port for scheme is elided`() {
        assertEquals("api.example.com",
            EndpointFormatter.format("api.example.com", 443, 443))
        assertEquals("api.example.com",
            EndpointFormatter.format("api.example.com", 80, 80))
    }

    @Test
    fun `non-default port is appended`() {
        assertEquals("api.example.com:8080",
            EndpointFormatter.format("api.example.com", 8080, 443))
        assertEquals("api.example.com:8443",
            EndpointFormatter.format("api.example.com", 8443, 80))
    }

    @Test
    fun `raw IPv4 is preserved verbatim`() {
        assertEquals("192.168.1.5",
            EndpointFormatter.format("192.168.1.5", 443, 443))
        assertEquals("192.168.1.5:9000",
            EndpointFormatter.format("192.168.1.5", 9000, 443))
    }

    @Test
    fun `IPv6 literal survives (okhttp already canonicalises brackets)`() {
        assertEquals("[::1]:9000",
            EndpointFormatter.format("[::1]", 9000, 443))
    }

    @Test
    fun `unknown host with port falls back to marker plus port`() {
        assertEquals("<unknown>:9000",
            EndpointFormatter.format(null, 9000, -1))
        assertEquals("<unknown>:9000",
            EndpointFormatter.format("", 9000, 443))
        assertEquals("<unknown>:9000",
            EndpointFormatter.format("   ", 9000, 80))
    }

    @Test
    fun `unknown host with no port falls back to marker only`() {
        assertEquals("<unknown>",
            EndpointFormatter.format(null, -1, -1))
        assertEquals("<unknown>",
            EndpointFormatter.format(null, 0, 443))
        assertEquals("<unknown>",
            EndpointFormatter.format("", -1, 80))
    }

    @Test
    fun `port equals default even when scheme unknown - scheme default -1 keeps port`() {
        assertEquals("api.example.com:443",
            EndpointFormatter.format("api.example.com", 443, -1))
    }

    @Test
    fun `negative or zero port is treated as absent`() {
        assertEquals("api.example.com",
            EndpointFormatter.format("api.example.com", -1, 443))
        assertEquals("api.example.com",
            EndpointFormatter.format("api.example.com", 0, 443))
    }
}
