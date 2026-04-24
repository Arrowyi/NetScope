package indi.arrowyi.netscope.plugin

import org.gradle.api.logging.Logger
import org.gradle.api.logging.Logging
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.util.CheckClassAdapter
import java.io.PrintWriter
import java.io.StringWriter

/**
 * v3.0.0 regression guard for the 3-arg WebSocket rewrite. The bytecode
 * manipulation at each `newWebSocket` callsite now has to:
 *
 *   1. shuffle the original stack `(client, request, listener)` into two
 *      local-variable slots,
 *   2. emit two `INVOKESTATIC`s to extract `endpoint` and `path` from
 *      the request and stash them in their own slots,
 *   3. push the wrapped listener and re-issue `newWebSocket`,
 *   4. SWAP the returned WebSocket under `endpoint` and `path` so
 *      `wrapWebSocket(endpoint, path, ws)` can run in natural arg order.
 *
 * This test synthesises a tiny class with one fake `newWebSocket`
 * invocation, runs the full [NetScopeTransform.tryTransform] pipeline
 * on it, and asserts:
 *
 *   - the output bytes contain the new helper names `endpointOf`,
 *     `pathOf`, `wrapListener` with the 3-arg descriptor and
 *     `wrapWebSocket` with the 3-arg descriptor, AND
 *   - [CheckClassAdapter] accepts the output class (stack size,
 *     max-locals, frames). This is the D8-killer we want to catch
 *     BEFORE shipping to Denali.
 */
class OkHttpWebSocketInstrumenterTest {

    private val log: Logger = Logging.getLogger("OkHttpWebSocketInstrumenterTest")
    private val transform = NetScopeTransform(log)

    @Test
    fun `newWebSocket call site is rewritten with 3-arg endpoint, path, x helpers`() {
        val bytes = syntheticNewWebSocketCaller()
        val out = transform.tryTransform(bytes, "com/example/WsCaller.class")

        assertNotNull("class calling newWebSocket must be rewritten", out)
        val stringForm = readableText(out!!)

        assertTrue(
            "rewrite must call NetScopeWebSocket.endpointOf(Request) : String",
            stringForm.contains("endpointOf") && stringForm.contains("(Lokhttp3/Request;)Ljava/lang/String;")
        )
        assertTrue(
            "rewrite must call NetScopeWebSocket.pathOf(Request) : String",
            stringForm.contains("pathOf")
        )
        assertTrue(
            "wrapListener must be invoked with the 3-arg (String, String, WebSocketListener) descriptor",
            stringForm.contains(
                "(Ljava/lang/String;Ljava/lang/String;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocketListener;"
            )
        )
        assertTrue(
            "wrapWebSocket must be invoked with the 3-arg (String, String, WebSocket) descriptor",
            stringForm.contains(
                "(Ljava/lang/String;Ljava/lang/String;Lokhttp3/WebSocket;)Lokhttp3/WebSocket;"
            )
        )
    }

    @Test
    fun `rewritten class passes ASM CheckClassAdapter verification`() {
        val bytes = syntheticNewWebSocketCaller()
        val out = transform.tryTransform(bytes, "com/example/WsCaller.class")
        assertNotNull(out)

        // CheckClassAdapter prints nothing when verification passes; it
        // either throws or prints a stack-trace on the PrintWriter on
        // failure. We capture the PrintWriter and assert the output is
        // empty — catches structural bytecode errors (stack under/overflow,
        // missing frames, wrong local index) that would crash D8 later.
        val sw = StringWriter()
        val reportWriter = PrintWriter(sw)
        CheckClassAdapter.verify(
            ClassReader(out!!),
            /* printResults = */ false,
            reportWriter
        )
        val report = sw.toString()
        assertTrue(
            "CheckClassAdapter must not emit a failure report for the rewritten class.\n$report",
            report.isBlank()
        )
    }

    // ── Fixture ──────────────────────────────────────────────────────

    /**
     * Build a synthetic class whose `foo(OkHttpClient, Request,
     * WebSocketListener)` body contains exactly one INVOKEVIRTUAL
     * `okhttp3/OkHttpClient#newWebSocket(Request,WebSocketListener)Lokhttp3/WebSocket;`
     * and nothing else.
     */
    private fun syntheticNewWebSocketCaller(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(
            Opcodes.V1_8, Opcodes.ACC_PUBLIC, "com/example/WsCaller", null,
            "java/lang/Object", null
        )
        val mv: MethodVisitor = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "foo",
            "(Lokhttp3/OkHttpClient;Lokhttp3/Request;Lokhttp3/WebSocketListener;)V",
            null, null
        )
        mv.visitCode()
        mv.visitVarInsn(Opcodes.ALOAD, 0)    // client
        mv.visitVarInsn(Opcodes.ALOAD, 1)    // request
        mv.visitVarInsn(Opcodes.ALOAD, 2)    // listener
        mv.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "okhttp3/OkHttpClient",
            "newWebSocket",
            "(Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;",
            false
        )
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    /**
     * Read the class's constant-pool names / descriptors as a single
     * string, so the test can assert the rewrite embedded the expected
     * helper references. Avoids pulling in asm-util's full Textifier.
     */
    private fun readableText(bytes: ByteArray): String {
        val sb = StringBuilder()
        val reader = ClassReader(bytes)
        reader.accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int, name: String?, descriptor: String?,
                signature: String?, exceptions: Array<out String>?
            ): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                override fun visitMethodInsn(
                    opcode: Int, owner: String?, nameIn: String?,
                    desc: String?, isInterface: Boolean
                ) {
                    sb.append(owner).append('.').append(nameIn).append(desc).append('\n')
                }
            }
        }, 0)
        return sb.toString()
    }
}
