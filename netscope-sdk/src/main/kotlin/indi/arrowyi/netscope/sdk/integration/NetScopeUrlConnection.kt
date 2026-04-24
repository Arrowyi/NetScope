package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
import indi.arrowyi.netscope.sdk.internal.EndpointFormatter
import indi.arrowyi.netscope.sdk.internal.PathNormalizer
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URL
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
 *
 * **Local-scheme denylist (AOP-G16).** The bytecode rewrite happens
 * unconditionally on every `URLConnection.getInputStream()` /
 * `getOutputStream()` call site, so at runtime we also see connections
 * opened on `file:`, `content:`, `asset:`, `android.resource:`,
 * `data:`, ... — reads that never touch the radio and must not be
 * attributed as network traffic. We skip those and pass the caller's
 * stream through verbatim (no counting, no `flowEnd`).
 *
 * Everything *not* on the local denylist is considered network traffic.
 * That includes the obvious HTTP/HTTPS, but also `ftp:`, `sftp:`, and
 * any custom scheme that actually opens a socket — the user asked us
 * not to under-report those.
 *
 * `jar:` is resolved by inner URL: `jar:file:/…!/x` is local,
 * `jar:http://host/x.jar!/entry` is network.
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
     * Returns `null` when the connection must be treated as
     * non-network, which means "pass through un-instrumented":
     *  - the connection has no URL at all;
     *  - the URL's scheme is on the local-scheme denylist (see
     *    [isLocalUrl] and AOP-G16).
     */
    private fun endpointAndPath(conn: URLConnection): Pair<String, String>? {
        val url = conn.url ?: return null
        if (isLocalUrl(url)) return null
        val host = EndpointFormatter.format(url.host, url.port, url.defaultPort)
        val path = PathNormalizer.normalize(url.path)
        return host to path
    }

    /**
     * True iff [url] points at something local to the device — a file,
     * content provider, app asset, data URI, etc. — and therefore must
     * not be counted as network traffic (AOP-G16).
     *
     * Everything *not* on this denylist is assumed network. That keeps
     * exotic-but-real network transports (`ftp:`, `sftp:`, `gopher:`,
     * custom scheme over a socket) counted, which matches the user
     * expectation that anything that touches the wire shows up.
     *
     * `jar:` is unwrapped once to inspect its inner URL:
     *  - `jar:file:/…!/x`          → local
     *  - `jar:http://host/x.jar!/y` → network (inner URL is remote)
     */
    internal fun isLocalUrl(url: URL): Boolean {
        val scheme = url.protocol?.lowercase() ?: return true
        if (isLocalScheme(scheme)) return true
        if (scheme == "jar") {
            val inner = jarInnerScheme(url) ?: return true
            return isLocalScheme(inner)
        }
        return false
    }

    private fun isLocalScheme(scheme: String): Boolean = when (scheme) {
        "file",
        "content",
        "asset",
        "android.resource",
        "android-app",
        "data",
        "res",
        "resource" -> true
        else -> false
    }

    /**
     * Extract the scheme of the URL wrapped inside a `jar:` URL.
     * `java.net.URL` does not parse this for us — the `jar:` spec
     * is literally `jar:<inner-url>!/<entry>`, where the inner URL
     * is an arbitrary RFC-2396 URL.
     *
     * Returns `null` when parsing fails, in which case the caller
     * should default to "treat as local" — the safe bet for an
     * unrecognised jar layout is to not emit spurious traffic.
     */
    private fun jarInnerScheme(url: URL): String? {
        val spec = url.toExternalForm()
        if (!spec.startsWith("jar:", ignoreCase = true)) return null
        val body = spec.substring(4)
        val bang = body.indexOf("!/")
        val inner = if (bang >= 0) body.substring(0, bang) else body
        val colon = inner.indexOf(':')
        if (colon <= 0) return null
        return inner.substring(0, colon).lowercase()
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
