package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
import indi.arrowyi.netscope.sdk.internal.EndpointFormatter
import indi.arrowyi.netscope.sdk.internal.PathNormalizer
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URLConnection

/**
 * Helper invoked by the Gradle Transform's rewrite of every
 * `java.net.URL#openConnection()` call site.
 *
 * Design: the Transform only touches the *call site*, not the
 * `URLConnection` subclass. We cannot replace the returned object with
 * a different class because Android / app code reads subclass-specific
 * methods (`HttpURLConnection.getResponseCode`, etc.). Instead we keep
 * the original object and install counting wrappers **on the streams
 * it returns** via [wrapInputStream] / [wrapOutputStream].
 *
 * v3.0.0+: wrappers now key on `(host, path)` rather than just `host`.
 * Host goes through [EndpointFormatter] so non-default ports survive
 * and unresolvable connections surface as `<unknown>` / `<unknown>:port`.
 * Path goes through [PathNormalizer] so high-cardinality IDs collapse.
 */
object NetScopeUrlConnection {

    @JvmStatic
    fun wrap(conn: URLConnection?): URLConnection? = conn

    /**
     * The Transform calls this immediately after `getInputStream()`.
     * We extract endpoint + path from `conn.url` and wrap the stream
     * in a counting decorator. Idempotent when already marker-typed.
     */
    @JvmStatic
    fun wrapInputStream(conn: URLConnection?, stream: InputStream?): InputStream? {
        if (conn == null || stream == null) return stream
        if (stream is NetScopeInstrumented) return stream
        val (host, path) = endpointAndPath(conn) ?: return stream
        return CountingInputStream(stream, host, path)
    }

    /** Companion of [wrapInputStream] for `getOutputStream()`. */
    @JvmStatic
    fun wrapOutputStream(conn: URLConnection?, stream: OutputStream?): OutputStream? {
        if (conn == null || stream == null) return stream
        if (stream is NetScopeInstrumented) return stream
        val (host, path) = endpointAndPath(conn) ?: return stream
        return CountingOutputStream(stream, host, path)
    }

    /**
     * Resolve the `(host, path)` key from a [URLConnection]. Uses
     * `URL.getPort()` (−1 if unset) against `URL.getDefaultPort()`
     * (scheme's default or −1) so non-default ports are surfaced.
     *
     * Returns `null` if the connection has no URL at all — in that
     * case the caller passes through un-instrumented rather than
     * emit spurious `<unknown>` traffic.
     */
    private fun endpointAndPath(conn: URLConnection): Pair<String, String>? {
        val url = conn.url ?: return null
        val host = EndpointFormatter.format(url.host, url.port, url.defaultPort)
        val path = PathNormalizer.normalize(url.path)
        return host to path
    }

    private class CountingInputStream(
        delegate: InputStream,
        private val host: String,
        private val path: String
    ) : FilterInputStream(delegate), NetScopeInstrumented {
        private var ended: Boolean = false

        override fun read(): Int {
            val b = super.read()
            if (b >= 0) NetScope.reportRx(host, path, 1L)
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val n = super.read(b, off, len)
            if (n > 0) NetScope.reportRx(host, path, n.toLong())
            return n
        }

        override fun close() {
            try {
                super.close()
            } finally {
                if (!ended) {
                    ended = true
                    NetScope.reportFlowEnd(host, path, 0L, 0L)
                }
            }
        }
    }

    private class CountingOutputStream(
        delegate: OutputStream,
        private val host: String,
        private val path: String
    ) : FilterOutputStream(delegate), NetScopeInstrumented {
        override fun write(b: Int) {
            super.out.write(b)
            NetScope.reportTx(host, path, 1L)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            super.out.write(b, off, len)
            if (len > 0) NetScope.reportTx(host, path, len.toLong())
        }
    }
}
