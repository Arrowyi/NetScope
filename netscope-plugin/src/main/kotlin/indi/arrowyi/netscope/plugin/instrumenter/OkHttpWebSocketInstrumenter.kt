package indi.arrowyi.netscope.plugin.instrumenter

import org.gradle.api.logging.Logger
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Wraps every `OkHttpClient#newWebSocket(Request, WebSocketListener)`
 * callsite so that:
 *
 *   1. the `WebSocketListener` argument is replaced by
 *      `NetScopeWebSocket.wrapListener(endpoint, path, listener)`
 *      — to count inbound frames;
 *   2. the returned `WebSocket` is replaced by
 *      `NetScopeWebSocket.wrapWebSocket(endpoint, path, ws)`
 *      — to count outbound frames on `send(...)`.
 *
 * `endpoint` (host optionally with `:port`) and `path` (normalised URL
 * path) are extracted from the `Request` via
 * `NetScopeWebSocket.endpointOf(Request) : String` and
 * `NetScopeWebSocket.pathOf(Request) : String`. Both are invoked once
 * per call site and the results stashed in local slots.
 *
 * Stack/local plan at the call site (top of stack on the right):
 *
 * Original:
 *   ..., client, request, listener
 *   INVOKEVIRTUAL OkHttpClient.newWebSocket
 *       (Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;
 *
 * Rewritten:
 *   ..., client, request, listener
 *   ASTORE slotListener                 ; ..., client, request
 *   ASTORE slotRequest                  ; ..., client
 *   ALOAD  slotRequest                  ; ..., client, request
 *   INVOKESTATIC endpointOf             ; ..., client, endpoint
 *   ASTORE slotEndpoint                 ; ..., client
 *   ALOAD  slotRequest                  ; ..., client, request
 *   INVOKESTATIC pathOf                 ; ..., client, path
 *   ASTORE slotPath                     ; ..., client
 *   ALOAD  slotRequest                  ; ..., client, request
 *   ALOAD  slotEndpoint                 ; ..., client, request, endpoint
 *   ALOAD  slotPath                     ; ..., client, request, endpoint, path
 *   ALOAD  slotListener                 ; ..., client, request, endpoint, path, listener
 *   INVOKESTATIC wrapListener           ; ..., client, request, wrappedListener
 *   INVOKEVIRTUAL newWebSocket          ; ..., webSocket
 *   ALOAD  slotEndpoint
 *   SWAP                                ; ..., endpoint, webSocket → endpoint, ws on top
 *   ; actually we push in order (endpoint, path, ws):
 *   ALOAD  slotPath
 *   SWAP                                ; ..., endpoint, path, ws
 *   INVOKESTATIC wrapWebSocket          ; ..., wrappedWebSocket
 *
 * Slots used: `slotRequest`, `slotListener`, `slotEndpoint`, `slotPath`.
 * Picked far above any realistic method's own locals; COMPUTE_MAXS
 * widens maxLocals. Stack frames stay trivially verifiable because we
 * reserve only a small window around one bytecode instruction.
 */
internal class OkHttpWebSocketInstrumenter(
    api: Int,
    cv: ClassVisitor,
    private val owningClass: String,
    private val log: Logger
) : ClassVisitor(api, cv) {

    override fun visitMethod(
        access: Int, name: String, descriptor: String,
        signature: String?, exceptions: Array<String>?
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        return WsMethodVisitor(api, mv, owningClass, name, log)
    }

    private class WsMethodVisitor(
        api: Int,
        mv: MethodVisitor,
        private val owningClass: String,
        private val methodName: String,
        private val log: Logger
    ) : MethodVisitor(api, mv) {

        // Slots far above anything a sane method uses. COMPUTE_MAXS
        // expands maxLocals to cover.
        private val slotRequest  = 200
        private val slotListener = 202
        private val slotEndpoint = 204
        private val slotPath     = 206

        override fun visitMethodInsn(
            opcode: Int, ownerIn: String, nameIn: String,
            descriptorIn: String, isInterface: Boolean
        ) {
            val isNewWebSocket = (
                opcode == Opcodes.INVOKEVIRTUAL
                && ownerIn == OK_CLIENT
                && nameIn == "newWebSocket"
                && descriptorIn == NEWWS_DESC
            )
            if (!isNewWebSocket) {
                super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
                return
            }

            // Stack in: ..., client, request, listener
            super.visitVarInsn(Opcodes.ASTORE, slotListener)  // ..., client, request
            super.visitVarInsn(Opcodes.ASTORE, slotRequest)   // ..., client

            // endpoint = NetScopeWebSocket.endpointOf(request)
            super.visitVarInsn(Opcodes.ALOAD, slotRequest)
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "endpointOf",
                "(Lokhttp3/Request;)Ljava/lang/String;", false
            )
            super.visitVarInsn(Opcodes.ASTORE, slotEndpoint)

            // path = NetScopeWebSocket.pathOf(request)
            super.visitVarInsn(Opcodes.ALOAD, slotRequest)
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "pathOf",
                "(Lokhttp3/Request;)Ljava/lang/String;", false
            )
            super.visitVarInsn(Opcodes.ASTORE, slotPath)

            // Push wrapped listener:
            // wrapListener(endpoint, path, listener) -> WebSocketListener
            super.visitVarInsn(Opcodes.ALOAD, slotRequest)    // ..., client, request
            super.visitVarInsn(Opcodes.ALOAD, slotEndpoint)
            super.visitVarInsn(Opcodes.ALOAD, slotPath)
            super.visitVarInsn(Opcodes.ALOAD, slotListener)
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "wrapListener",
                "(Ljava/lang/String;Ljava/lang/String;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocketListener;",
                false
            )
            // Stack: ..., client, request, wrappedListener

            // Original newWebSocket call with wrapped listener.
            super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
            // Stack: ..., webSocket

            // Wrap the returned WebSocket:
            // wrapWebSocket(endpoint, path, ws) -> WebSocket
            // Stack target before the call: ..., endpoint, path, ws
            super.visitVarInsn(Opcodes.ALOAD, slotEndpoint)   // ..., ws, endpoint
            super.visitInsn(Opcodes.SWAP)                     // ..., endpoint, ws
            super.visitVarInsn(Opcodes.ALOAD, slotPath)       // ..., endpoint, ws, path
            super.visitInsn(Opcodes.SWAP)                     // ..., endpoint, path, ws
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "wrapWebSocket",
                "(Ljava/lang/String;Ljava/lang/String;Lokhttp3/WebSocket;)Lokhttp3/WebSocket;",
                false
            )
            // Stack: ..., wrappedWs

            log.info("[NetScope] wrapped newWebSocket at $owningClass.$methodName")
        }
    }

    companion object {
        private const val OK_CLIENT = "okhttp3/OkHttpClient"
        private const val HELPER = "indi/arrowyi/netscope/sdk/integration/NetScopeWebSocket"
        private const val NEWWS_DESC =
            "(Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;"
    }
}
