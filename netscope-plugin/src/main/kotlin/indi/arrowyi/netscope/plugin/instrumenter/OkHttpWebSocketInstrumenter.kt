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
 *      `NetScopeWebSocket.wrapListener(host, listener)`
 *      — to count inbound frames;
 *   2. the returned `WebSocket` is replaced by
 *      `NetScopeWebSocket.wrapWebSocket(host, ws)`
 *      — to count outbound frames on `send(...)`.
 *
 * `host` is extracted from the `Request` via
 * `NetScopeWebSocket.hostOf(Request) : String`. This requires
 * duplicating the `Request` reference on the stack.
 *
 * Bytecode plan at the call site (stack notation, top on the right):
 *
 * Original:
 *   ..., client, request, listener
 *   INVOKEVIRTUAL OkHttpClient.newWebSocket
 *       (Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;
 *
 * Rewritten:
 *   ..., client, request, listener
 *   ; wrap listener:
 *   SWAP                            ; ..., client, listener, request
 *   DUP                             ; ..., client, listener, request, request
 *   INVOKESTATIC  hostOf            ; ..., client, listener, request, host
 *   DUP_X2                          ; ..., client, host, listener, request, host
 *   POP                             ; ..., client, host, listener, request
 *   SWAP                            ; ..., client, host, request, listener
 *   ; now we need host available AGAIN as arg0 for wrapListener,
 *   ; but it's three slots deep. Simpler: use a LocalVar slot.
 *
 * The swap dance is ugly. A much cleaner implementation stores the
 * `Request` and `listener` into local-variable slots. That is what we
 * do. It takes 2 free slots; we allocate using [newLocal] via
 * `asm-commons` LocalVariablesSorter... but importing that for this
 * one use case bloats the plugin. Instead we use ASM's low-level local
 * index by picking a high arbitrary index and relying on
 * `COMPUTE_MAXS` to widen the method's local-var count.
 *
 * Implementation uses `visitVarInsn` ASTORE/ALOAD into slots
 * `maxLocalSlot + 1` and `+ 2`; since this method reserves only a
 * small window around one bytecode instruction, stack frames stay
 * trivially verifiable. `COMPUTE_MAXS` fixes the frame size.
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

        // Use slots far above anything a sane method uses for its own
        // locals. COMPUTE_MAXS will expand maxLocals accordingly.
        private val slotRequest = 200
        private val slotListener = 202
        private val slotHost = 204

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

            // Compute host.
            super.visitVarInsn(Opcodes.ALOAD, slotRequest)
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "hostOf",
                "(Lokhttp3/Request;)Ljava/lang/String;", false
            )
            super.visitVarInsn(Opcodes.ASTORE, slotHost)

            // Push wrapped listener.
            // wrapListener(host, listener) -> WebSocketListener
            super.visitVarInsn(Opcodes.ALOAD, slotRequest)    // ..., client, request
            super.visitVarInsn(Opcodes.ALOAD, slotHost)
            super.visitVarInsn(Opcodes.ALOAD, slotListener)
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "wrapListener",
                "(Ljava/lang/String;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocketListener;",
                false
            )
            // Stack: ..., client, request, wrappedListener

            // Original newWebSocket call with wrapped listener.
            super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
            // Stack: ..., webSocket

            // Wrap the returned WebSocket.
            super.visitVarInsn(Opcodes.ALOAD, slotHost)
            super.visitInsn(Opcodes.SWAP)                     // ..., host, ws
            super.visitMethodInsn(
                Opcodes.INVOKESTATIC, HELPER, "wrapWebSocket",
                "(Ljava/lang/String;Lokhttp3/WebSocket;)Lokhttp3/WebSocket;",
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
