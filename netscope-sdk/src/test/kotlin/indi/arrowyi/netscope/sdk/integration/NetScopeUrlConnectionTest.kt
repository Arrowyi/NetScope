package indi.arrowyi.netscope.sdk.integration

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URL
import java.net.URLConnection

/**
 * JVM tests for the [NetScopeUrlConnection] scheme policy (AOP-G16).
 *
 * Rule (v3.0.1+): local-scheme denylist rather than http(s) allowlist.
 * Anything that touches the network — HTTP/HTTPS, FTP, SFTP, custom
 * socket-backed schemes — gets a counting wrapper. Purely local
 * sources (`file:`, `content:`, `asset:`, `data:`, `android.resource:`,
 * `res:`, `jar:file:`) are passed through verbatim.
 */
class NetScopeUrlConnectionTest {

    private fun stubConn(url: URL): URLConnection = object : URLConnection(url) {
        override fun connect() = Unit
    }

    // ---------------------------------------------------------------- network

    @Test fun httpSchemeWrapsInputStream() {
        val conn = stubConn(URL("http://api.example.com/v1/things"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertNotSame("expected a wrapper for http://", raw, wrapped)
        assertTrue(wrapped is NetScopeInstrumented)
    }

    @Test fun httpsSchemeWrapsInputStream() {
        val conn = stubConn(URL("https://api.example.com/v1/things"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertTrue(wrapped is NetScopeInstrumented)
    }

    @Test fun ftpSchemeIsCountedBecauseItTouchesTheWire() {
        val conn = stubConn(URL("ftp://host.example.com/foo"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertTrue("ftp:// is a network transport and must be counted",
            wrapped is NetScopeInstrumented)
    }

    @Test fun httpSchemeWrapsOutputStream() {
        val conn = stubConn(URL("http://api.example.com/v1/things"))
        val raw = ByteArrayOutputStream()
        val wrapped = NetScopeUrlConnection.wrapOutputStream(conn, raw)
        assertNotSame(raw, wrapped)
        assertTrue(wrapped is NetScopeInstrumented)
    }

    @Test fun mixedCaseHttpStillWraps() {
        val conn = stubConn(URL("HTTP://API.EXAMPLE.COM/things"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertTrue("scheme compare must be case-insensitive", wrapped is NetScopeInstrumented)
    }

    @Test fun jarWithHttpInnerSchemeIsCounted() {
        val conn = stubConn(URL("jar:http://cdn.example.com/libs/x.jar!/res.txt"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertTrue("jar: over http must be counted — it reads from the network",
            wrapped is NetScopeInstrumented)
    }

    // ------------------------------------------------------------------ local

    @Test fun fileSchemePassesThroughInputStream() {
        val conn = stubConn(URL("file:/data/local/foo.txt"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertSame("file:// must not be counted", raw, wrapped)
        assertFalse(wrapped is NetScopeInstrumented)
    }

    @Test fun fileSchemePassesThroughOutputStream() {
        val conn = stubConn(URL("file:/data/local/foo.txt"))
        val raw = ByteArrayOutputStream()
        val wrapped = NetScopeUrlConnection.wrapOutputStream(conn, raw)
        assertSame("file:// outputs must not be counted", raw, wrapped)
    }

    @Test fun jarWithFileInnerSchemePassesThrough() {
        val conn = stubConn(URL("jar:file:/tmp/x.jar!/res.txt"))
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(conn, raw)
        assertSame("jar:file: is reading a local archive — must not be counted",
            raw, wrapped)
    }

    @Test fun nullConnectionPassesThrough() {
        val raw = ByteArrayInputStream(ByteArray(0))
        val wrapped = NetScopeUrlConnection.wrapInputStream(null, raw)
        assertSame(raw, wrapped)
    }

    // ----------------------- helper: isLocalUrl surface (internal but visible)

    @Test fun isLocalUrl_deniesKnownLocalSchemes() {
        listOf(
            "file:/a",
            "jar:file:/a!/b"
        ).forEach {
            assertTrue("$it must be classified local",
                NetScopeUrlConnection.isLocalUrl(URL(it)))
        }
    }

    @Test fun isLocalUrl_allowsNetworkSchemes() {
        listOf(
            "http://a",
            "https://a",
            "ftp://a",
            "jar:http://a!/b"
        ).forEach {
            assertFalse("$it must be classified network",
                NetScopeUrlConnection.isLocalUrl(URL(it)))
        }
    }
}
