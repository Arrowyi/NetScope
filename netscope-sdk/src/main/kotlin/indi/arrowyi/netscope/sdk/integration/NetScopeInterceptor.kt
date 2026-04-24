package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
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
 * OkHttp [Interceptor] that counts request/response bytes per-domain.
 *
 * Wired in one of two ways:
 *   1. The `indi.arrowyi.netscope` Gradle plugin instruments every
 *      `OkHttpClient.Builder#build()` call site to append us via
 *      [NetScopeInterceptorInjector.addIfMissing] (the recommended
 *      path — zero host-code change).
 *   2. The host adds us manually:
 *      `builder.addInterceptor(NetScopeInterceptor)`.
 *
 * Accuracy notes:
 *  - Request body bytes are counted by wrapping the user-supplied
 *    `RequestBody` with a counting `Sink` passthrough. This sees
 *    exactly the bytes OkHttp writes to the wire, post-compression
 *    (if the app did its own) but pre-TLS. Matches "application-layer"
 *    traffic volume, which is what per-domain stats are about.
 *  - Response body bytes are counted via a counting `Source`. Chunked
 *    / streamed bodies count correctly because we count as bytes flow
 *    through, not via `.string().length`.
 *  - Flow-end (`reportFlowEnd`) fires when the response body is closed
 *    — that's the end of one logical request/response, same semantics
 *    as "TCP close" for simple flows.
 *
 * Application-level interceptor (NOT a network interceptor) by
 * intention: this way we see the request body before any OkHttp-level
 * gzip / encoding adds bytes, and the response body after any
 * OkHttp-level decoding removes bytes. Callers' "perceived" traffic
 * volume matches the stats.
 */
object NetScopeInterceptor : Interceptor, NetScopeInstrumented {

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val host = originalRequest.url.host

        // Wrap the request body if present.
        val countedReq: Request = originalRequest.body?.let { body ->
            originalRequest.newBuilder()
                .method(originalRequest.method, CountingRequestBody(body, host))
                .build()
        } ?: originalRequest

        val response: Response = chain.proceed(countedReq)

        // Wrap the response body.
        val originalResponseBody = response.body ?: return response
        val countedBody = CountingResponseBody(originalResponseBody, host)
        return response.newBuilder().body(countedBody).build()
    }

    private class CountingRequestBody(
        private val delegate: RequestBody,
        private val host: String
    ) : RequestBody(), NetScopeInstrumented {
        override fun contentType(): MediaType? = delegate.contentType()
        override fun contentLength(): Long = delegate.contentLength()
        override fun isDuplex(): Boolean = delegate.isDuplex()
        override fun isOneShot(): Boolean = delegate.isOneShot()

        override fun writeTo(sink: BufferedSink) {
            val counting = CountingSink(sink, host).buffer()
            delegate.writeTo(counting)
            counting.flush()
        }
    }

    private class CountingSink(delegate: Sink, private val host: String)
        : ForwardingSink(delegate), NetScopeInstrumented {
        override fun write(source: Buffer, byteCount: Long) {
            super.write(source, byteCount)
            if (byteCount > 0) NetScope.reportTx(host, byteCount)
        }
    }

    private class CountingResponseBody(
        private val delegate: ResponseBody,
        private val host: String
    ) : ResponseBody(), NetScopeInstrumented {
        private var rxBytes: Long = 0L
        private var ended: Boolean = false
        private val countingSource: BufferedSource by lazy {
            CountingSource(delegate.source(), host) { delta ->
                rxBytes += delta
            }.buffer()
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
                    NetScope.reportFlowEnd(host, 0L, 0L)
                }
            }
        }
    }

    private class CountingSource(
        delegate: Source,
        private val host: String,
        private val onRead: (Long) -> Unit
    ) : ForwardingSource(delegate), NetScopeInstrumented {
        override fun read(sink: Buffer, byteCount: Long): Long {
            val n = super.read(sink, byteCount)
            if (n > 0) {
                NetScope.reportRx(host, n)
                onRead(n)
            }
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
