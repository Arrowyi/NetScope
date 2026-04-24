package indi.arrowyi.netscope.sdk.integration

import indi.arrowyi.netscope.sdk.NetScope
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString

/**
 * Build-time-wrapped OkHttp WebSocket helper.
 *
 * OkHttp's [WebSocketListener] only observes INBOUND frames. To count
 * outbound bytes we must also wrap the [WebSocket] instance returned by
 * `OkHttpClient.newWebSocket(...)`.
 *
 * The Gradle Transform rewrites every `OkHttpClient#newWebSocket`
 * callsite so that:
 *
 *   - the `WebSocketListener` argument is replaced with
 *     `NetScopeWebSocket.wrapListener(host, origListener)`,
 *   - the returned `WebSocket` is passed through
 *     `NetScopeWebSocket.wrapWebSocket(host, ws)`.
 *
 * The host is captured from the `Request.url.host` at callsite time —
 * the Transform emits a small prologue that reads it off the `Request`
 * before the original `newWebSocket` invocation.
 */
object NetScopeWebSocket {

    @JvmStatic
    fun hostOf(request: Request?): String =
        request?.url?.host ?: ""

    /**
     * Wrap a user [WebSocketListener] with one that counts inbound
     * bytes. The wrapped listener forwards all events to the original
     * verbatim.
     */
    @JvmStatic
    fun wrapListener(host: String, listener: WebSocketListener): WebSocketListener {
        if (listener is NetScopeInstrumented) return listener
        return CountingListener(host, listener)
    }

    /**
     * Wrap a [WebSocket] so that all outbound `send` calls are counted.
     */
    @JvmStatic
    fun wrapWebSocket(host: String, ws: WebSocket): WebSocket {
        if (ws is NetScopeInstrumented) return ws
        return CountingWebSocket(host, ws)
    }

    private class CountingListener(
        private val host: String,
        private val delegate: WebSocketListener
    ) : WebSocketListener(), NetScopeInstrumented {

        override fun onOpen(webSocket: WebSocket, response: Response) {
            delegate.onOpen(webSocket, response)
        }

        override fun onMessage(webSocket: WebSocket, text: String) {
            NetScope.reportRx(host, text.toByteArray(Charsets.UTF_8).size.toLong())
            delegate.onMessage(webSocket, text)
        }

        override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
            NetScope.reportRx(host, bytes.size.toLong())
            delegate.onMessage(webSocket, bytes)
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            delegate.onClosing(webSocket, code, reason)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
            try { delegate.onClosed(webSocket, code, reason) }
            finally { NetScope.reportFlowEnd(host, 0L, 0L) }
        }

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
            try { delegate.onFailure(webSocket, t, response) }
            finally { NetScope.reportFlowEnd(host, 0L, 0L) }
        }
    }

    private class CountingWebSocket(
        private val host: String,
        private val delegate: WebSocket
    ) : WebSocket, NetScopeInstrumented {
        override fun request(): Request = delegate.request()
        override fun queueSize(): Long = delegate.queueSize()

        override fun send(text: String): Boolean {
            val ok = delegate.send(text)
            if (ok) NetScope.reportTx(host, text.toByteArray(Charsets.UTF_8).size.toLong())
            return ok
        }

        override fun send(bytes: ByteString): Boolean {
            val ok = delegate.send(bytes)
            if (ok) NetScope.reportTx(host, bytes.size.toLong())
            return ok
        }

        override fun close(code: Int, reason: String?): Boolean = delegate.close(code, reason)
        override fun cancel() = delegate.cancel()
    }
}
