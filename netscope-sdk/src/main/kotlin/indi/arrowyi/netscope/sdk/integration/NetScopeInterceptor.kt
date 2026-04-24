package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
import indi.arrowyi.netscope.sdk.internal.EndpointFormatter
import indi.arrowyi.netscope.sdk.internal.PathNormalizer
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSink
import okio.BufferedSource
import okio.ForwardingSink
import okio.ForwardingSource
import okio.Sink
import okio.Source
import okio.buffer

/**
 * OkHttp [Interceptor] that counts request/response bytes per-API
 * (v3.0.0+).
 *
 * For every request we derive a `(host, path)` key:
 *   - `host` = [EndpointFormatter.format] of `url.host`, `url.port()`
 *     and `HttpUrl.defaultPort(url.scheme)`, so non-default ports
 *     (e.g. `:8080`) are preserved and defaults (80/443) are elided.
 *     Raw IPs pass through verbatim.
 *   - `path` = [PathNormalizer.normalize] of `url.encodedPath`, which
 *     templates numeric IDs / UUIDs / hex hashes and drops
 *     query/fragment.
 *
 * Accuracy notes:
 *  - Request body bytes are counted by wrapping the user-supplied
 *    `RequestBody` with a counting `Sink` passthrough (bytes OkHttp
 *    writes to the wire, post app-level compression, pre TLS).
 *  - Response body bytes are counted via a counting `Source`; chunked /
 *    streamed bodies count correctly because we tally as bytes flow.
 *  - Flow-end fires when the response body is closed.
 *
 * Application-level interceptor by intention, so the request body is
 * observed before OkHttp-level gzip and the response body after OkHttp
 * decoding — matching the caller's perception of traffic volume.
 *
 * Wired via the Gradle plugin (`OkHttpClient.Builder#build` is rewritten
 * to append us) or manually (`builder.addInterceptor(NetScopeInterceptor)`).
 */
object NetScopeInterceptor : Interceptor, NetScopeInstrumented {

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val url = originalRequest.url
        val host = endpointOf(url)
        val path = PathNormalizer.normalize(url.encodedPath)

        val countedReq: Request = originalRequest.body?.let { body ->
            originalRequest.newBuilder()
                .method(originalRequest.method, CountingRequestBody(body, host, path))
                .build()
        } ?: originalRequest

        val response: Response = chain.proceed(countedReq)

        val originalResponseBody = response.body ?: return response
        val countedBody = CountingResponseBody(originalResponseBody, host, path)
        return response.newBuilder().body(countedBody).build()
    }

    private fun endpointOf(url: HttpUrl): String {
        val default = HttpUrl.defaultPort(url.scheme)
        return EndpointFormatter.format(url.host, url.port, default)
    }

    private class CountingRequestBody(
        private val delegate: RequestBody,
        private val host: String,
        private val path: String
    ) : RequestBody(), NetScopeInstrumented {
        override fun contentType(): MediaType? = delegate.contentType()
        override fun contentLength(): Long = delegate.contentLength()
        override fun isDuplex(): Boolean = delegate.isDuplex()
        override fun isOneShot(): Boolean = delegate.isOneShot()

        override fun writeTo(sink: BufferedSink) {
            val counting = CountingSink(sink, host, path).buffer()
            delegate.writeTo(counting)
            counting.flush()
        }
    }

    private class CountingSink(
        delegate: Sink,
        private val host: String,
        private val path: String
    ) : ForwardingSink(delegate), NetScopeInstrumented {
        override fun write(source: Buffer, byteCount: Long) {
            super.write(source, byteCount)
            if (byteCount > 0) NetScope.reportTx(host, path, byteCount)
        }
    }

    private class CountingResponseBody(
        private val delegate: ResponseBody,
        private val host: String,
        private val path: String
    ) : ResponseBody(), NetScopeInstrumented {
        private var ended: Boolean = false
        private val countingSource: BufferedSource by lazy {
            CountingSource(delegate.source(), host, path).buffer()
        }
        override fun contentType(): MediaType? = delegate.contentType()
        override fun contentLength(): Long = delegate.contentLength()
        override fun source(): BufferedSource = countingSource
        override fun close() {
            try {
                delegate.close()
            } finally {
                if (!ended) {
                    ended = true
                    NetScope.reportFlowEnd(host, path, 0L, 0L)
                }
            }
        }
    }

    private class CountingSource(
        delegate: Source,
        private val host: String,
        private val path: String
    ) : ForwardingSource(delegate), NetScopeInstrumented {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val n = super.read(sink, byteCount)
            if (n > 0) NetScope.reportRx(host, path, n)
            return n
        }
    }
}

/**
 * Helper used by the Gradle Transform's synthetic call at every
 * `OkHttpClient.Builder.build()` site.
 *
 * Idempotent: walks `builder.interceptors()` looking for an instance
 * implementing [NetScopeInstrumented]. If found, does nothing.
 * Otherwise appends [NetScopeInterceptor].
 *
 * Explicitly a Java-visible static so the bytecode emitted by the
 * Transform stays simple (`INVOKESTATIC`).
 */
object NetScopeInterceptorInjector {
    @JvmStatic
    fun addIfMissing(builder: okhttp3.OkHttpClient.Builder): okhttp3.OkHttpClient.Builder {
        val interceptors = builder.interceptors()
        for (i in interceptors) {
            if (i is NetScopeInstrumented) return builder
        }
        builder.addInterceptor(NetScopeInterceptor)
        return builder
    }
}
