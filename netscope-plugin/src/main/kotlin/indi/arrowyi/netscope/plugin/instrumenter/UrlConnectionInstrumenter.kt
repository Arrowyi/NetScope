package indi.arrowyi.netscope.plugin.instrumenter

import org.gradle.api.logging.Logger
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Instruments `URLConnection#getInputStream()` / `getOutputStream()`
 * callsites so the returned stream is wrapped by a counting decorator.
 *
 * Why not `URL.openConnection()`: replacing the returned object would
 * require subclassing [java.net.URLConnection] — and for
 * `HttpURLConnection` we cannot subclass cleanly (package-private
 * methods, vendor-specific subclasses). Instead we wrap the two
 * byte-carrying accessors, which is both sufficient and safe.
 *
 * Transformation:
 * ```
 *   is = conn.getInputStream();
 *     → is = NetScopeUrlConnection.wrapInputStream(conn, conn.getInputStream());
 *   os = conn.getOutputStream();
 *     → os = NetScopeUrlConnection.wrapOutputStream(conn, conn.getOutputStream());
 * ```
 *
 * Bytecode shape for the input-stream case:
 *   Before:
 *     ALOAD conn
 *     INVOKEVIRTUAL URLConnection.getInputStream ()Ljava/io/InputStream;
 *   After:
 *     ALOAD conn
 *     DUP                 ; conn, conn
 *     INVOKEVIRTUAL       ; conn, stream
 *         URLConnection.getInputStream ()Ljava/io/InputStream;
 *     INVOKESTATIC        ; wrappedStream
 *         NetScopeUrlConnection.wrapInputStream
 *             (Ljava/net/URLConnection;Ljava/io/InputStream;)Ljava/io/InputStream;
 *
 * We emit the DUP BEFORE the original invocation so the helper gets
 * both `conn` (so it can read URL.host) and the stream.
 *
 * Note: `INVOKEVIRTUAL URLConnection.getInputStream` has descriptor
 * `()Ljava/io/InputStream;` and is present on every subclass (it's not
 * overridden virtually — subclasses just fill in behaviour). We match
 * on descriptor + method name regardless of receiver type to catch
 * `HttpURLConnection`, `HttpsURLConnection`, and friends uniformly.
 */
internal class UrlConnectionInstrumenter(
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
        return object : MethodVisitor(api, mv) {
            override fun visitMethodInsn(
                opcode: Int, ownerIn: String, nameIn: String,
                descriptorIn: String, isInterface: Boolean
            ) {
                val isGetInputStream = (nameIn == "getInputStream"
                        && descriptorIn == "()Ljava/io/InputStream;"
                        && isUrlConnectionOwner(ownerIn))
                val isGetOutputStream = (nameIn == "getOutputStream"
                        && descriptorIn == "()Ljava/io/OutputStream;"
                        && isUrlConnectionOwner(ownerIn))

                if (opcode == Opcodes.INVOKEVIRTUAL && (isGetInputStream || isGetOutputStream)) {
                    // Stack: ..., conn
                    super.visitInsn(Opcodes.DUP)                  // ..., conn, conn
                    super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
                    // Stack: ..., conn, stream
                    val (helper, helperDesc) = if (isGetInputStream) {
                        "wrapInputStream" to
                            "(Ljava/net/URLConnection;Ljava/io/InputStream;)Ljava/io/InputStream;"
                    } else {
                        "wrapOutputStream" to
                            "(Ljava/net/URLConnection;Ljava/io/OutputStream;)Ljava/io/OutputStream;"
                    }
                    super.visitMethodInsn(
                        Opcodes.INVOKESTATIC, HELPER_OWNER, helper, helperDesc, false
                    )
                    log.info("[NetScope] wrapped $nameIn in $owningClass.$name")
                    return
                }
                super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
            }
        }
    }

    /**
     * We want to catch calls whose *declared static receiver type* is
     * URLConnection or any of its subclasses. ASM gives us the static
     * owner at the call site, so we list the obvious ones explicitly.
     * This avoids rewriting random `getInputStream()` calls on Socket,
     * Process, Files, etc.
     */
    private fun isUrlConnectionOwner(internalName: String): Boolean {
        return internalName == "java/net/URLConnection"
            || internalName == "java/net/HttpURLConnection"
            || internalName == "javax/net/ssl/HttpsURLConnection"
    }

    companion object {
        private const val HELPER_OWNER =
            "indi/arrowyi/netscope/sdk/integration/NetScopeUrlConnection"
    }
}
