package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
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
 * it returns** via a lightweight registration:
 *
 *   - [wrap] stamps the connection so subsequent `getInputStream()` /
 *     `getOutputStream()` go through [wrapInputStream] / [wrapOutputStream].
 *   - The Transform rewrites call sites of those two methods too — see
 *     the comment on [wrapInputStream].
 *
 * The simpler approach (return a subclass that overrides the stream
 * accessors) doesn't work for `HttpURLConnection` because we'd need to
 * override package-private methods. So we instrument the reader
 * instead.
 */
object NetScopeUrlConnection {

    private val hostTag = ThreadLocal<String?>()

    /**
     * Pass-through on the object, but records the target host on a
     * thread-local so the adjacent [wrapInputStream] / [wrapOutputStream]
     * calls (also emitted by the Transform) know what to count against.
     *
     * If the connection is `null` or already instrumented, returns it
     * verbatim.
     */
    @JvmStatic
    fun wrap(conn: URLConnection?): URLConnection? {
        if (conn == null) return null
        // Can't add interface to an existing object — we rely on the
        // thread-local pairing below plus marker-typed streams.
        return conn
    }

    /**
     * The Transform calls this immediately after `getInputStream()` on
     * any `URLConnection`. We extract the host from the connection's
     * URL and wrap the stream in a counting decorator. Idempotent when
     * the stream is already marker-typed.
     */
    @JvmStatic
    fun wrapInputStream(conn: URLConnection?, stream: InputStream?): InputStream? {
        if (conn == null || stream == null) return stream
        if (stream is NetScopeInstrumented) return stream
        val host = conn.url?.host ?: return stream
        return CountingInputStream(stream, host)
    }

    /**
     * Companion of [wrapInputStream] for `getOutputStream()`.
     */
    @JvmStatic
    fun wrapOutputStream(conn: URLConnection?, stream: OutputStream?): OutputStream? {
        if (conn == null || stream == null) return stream
        if (stream is NetScopeInstrumented) return stream
        val host = conn.url?.host ?: return stream
        return CountingOutputStream(stream, host)
    }

    private class CountingInputStream(
        delegate: InputStream,
        private val host: String
    ) : FilterInputStream(delegate), NetScopeInstrumented {
        private var rxBytes: Long = 0L
        private var ended: Boolean = false

        override fun read(): Int {
            val b = super.read()
            if (b >= 0) { rxBytes += 1; NetScope.reportRx(host, 1L) }
            return b
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val n = super.read(b, off, len)
            if (n > 0) { rxBytes += n; NetScope.reportRx(host, n.toLong()) }
            return n
        }

        override fun close() {
            try {
                super.close()
            } finally {
                if (!ended) {
                    ended = true
                    NetScope.reportFlowEnd(host, 0L, 0L)
                }
            }
        }
    }

    private class CountingOutputStream(
        delegate: OutputStream,
        private val host: String
    ) : FilterOutputStream(delegate), NetScopeInstrumented {
        override fun write(b: Int) {
            super.out.write(b)
            NetScope.reportTx(host, 1L)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            super.out.write(b, off, len)
            if (len > 0) NetScope.reportTx(host, len.toLong())
        }
    }
}
