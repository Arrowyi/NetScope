package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
import indi.arrowyi.netscope.sdk.internal.EndpointFormatter
import indi.arrowyi.netscope.sdk.internal.PathNormalizer
import okhttp3.HttpUrl
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

/**
 * Build-time-wrapped OkHttp WebSocket helper.
 *
 * OkHttp's [WebSocketListener] only observes INBOUND frames. To count
 * outbound bytes we must also wrap the [WebSocket] instance returned
 * by `OkHttpClient.newWebSocket(...)`.
 *
 * The Gradle Transform rewrites every `OkHttpClient#newWebSocket`
 * callsite so that:
 *
 *   - the `WebSocketListener` argument is replaced with
 *     `NetScopeWebSocket.wrapListener(host, path, origListener)`,
 *   - the returned `WebSocket` is passed through
 *     `NetScopeWebSocket.wrapWebSocket(host, path, ws)`.
 *
 * `host` and `path` are extracted from the `Request.url` at callsite
 * time via [endpointOf] and [pathOf] — see
 * [indi.arrowyi.netscope.plugin.instrumenter.OkHttpWebSocketInstrumenter]
 * for the bytecode plan.
 *
 * v3.0.0+: added `path` parameter throughout. `endpointOf` replaces the
 * v2.x `hostOf` helper and applies [EndpointFormatter] (so a WSS over a
 * non-default port shows up as e.g. `ws.example.com:9443`).
 */
object NetScopeWebSocket {

    /**
     * Build the endpoint string (host with `:port` when non-default
     * for the scheme) from a request. `<unknown>` when the request
     * is null. Called at the WS callsite by the Transform-emitted
     * prologue.
     */
    @JvmStatic
    fun endpointOf(request: Request?): String {
        val url = request?.url ?: return EndpointFormatter.UNKNOWN_HOST
        val default = HttpUrl.defaultPort(url.scheme)
        return EndpointFormatter.format(url.host, url.port, default)
    }

    /**
     * Build the normalised path string from a request. `"/"` when the
     * request is null. Called at the WS callsite by the
     * Transform-emitted prologue, alongside [endpointOf].
     */
    @JvmStatic
    fun pathOf(request: Request?): String {
        val url = request?.url ?: return "/"
        return PathNormalizer.normalize(url.encodedPath)
    }

    /**
     * Wrap a user [WebSocketListener] with one that counts inbound
     * bytes. The wrapped listener forwards all events to the original
     * verbatim.
     */
    @JvmStatic
    fun wrapListener(host: String, path: String, listener: WebSocketListener): WebSocketListener {
        if (listener is NetScopeInstrumented) return listener
        return CountingListener(host, path, listener)
    }

    /** Wrap a [WebSocket] so that all outbound `send` calls are counted. */
    @JvmStatic
    fun wrapWebSocket(host: String, path: String, ws: WebSocket): WebSocket {
        if (ws is NetScopeInstrumented) return ws
        return CountingWebSocket(host, path, ws)
    }

    private class CountingListener(
        private val host: String,
        private val path: String,
        private val delegate: WebSocketListener
    ) : WebSocketListener(), NetScopeInstrumented {

        override fun onOpen(webSocket: WebSocket, response: Response) {
            delegate.onOpen(webSocket, response)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            NetScope.reportRx(host, path, text.toByteArray(Charsets.UTF_8).size.toLong())
            delegate.onMessage(webSocket, text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            NetScope.reportRx(host, path, bytes.size.toLong())
            delegate.onMessage(webSocket, bytes)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            delegate.onClosing(webSocket, code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            try { delegate.onClosed(webSocket, code, reason) }
            finally { NetScope.reportFlowEnd(host, path, 0L, 0L) }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            try { delegate.onFailure(webSocket, t, response) }
            finally { NetScope.reportFlowEnd(host, path, 0L, 0L) }
        }
    }

    private class CountingWebSocket(
        private val host: String,
        private val path: String,
        private val delegate: WebSocket
    ) : WebSocket, NetScopeInstrumented {
        override fun request(): Request = delegate.request()
        override fun queueSize(): Long = delegate.queueSize()

        override fun send(text: String): Boolean {
            val ok = delegate.send(text)
            if (ok) NetScope.reportTx(host, path, text.toByteArray(Charsets.UTF_8).size.toLong())
            return ok
        }

        override fun send(bytes: ByteString): Boolean {
            val ok = delegate.send(bytes)
            if (ok) NetScope.reportTx(host, path, bytes.size.toLong())
            return ok
        }

        override fun close(code: Int, reason: String?): Boolean = delegate.close(code, reason)
        override fun cancel() = delegate.cancel()
    }
}
