package indi.arrowyi.netscope.plugin

import org.gradle.api.logging.Logger
import org.gradle.api.logging.Logging
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.junit.Test

/**
 * Unit test for the v2.0.2 prefilter. The D8 `Invalid descriptor
 * char 'N'` crash on Denali was caused by piping non-target classes
 * through `ClassWriter(COMPUTE_FRAMES)`. The fix is that
 * [NetScopeTransform.tryTransform] must return `null` (= passthrough,
 * caller keeps original bytes) when the input class does not contain
 * any of the three target call sites.
 *
 * This test synthesises minimal classes via ASM (no dependency on
 * OkHttp / URLConnection being on the classpath) and asserts the
 * passthrough / rewrite invariant.
 */
class NetScopeTransformPrefilterTest {

    private val log: Logger = Logging.getLogger("NetScopeTransformPrefilterTest")
    private val transform = NetScopeTransform(log)

    @Test
    fun `class with no target call site is passthrough`() {
        val bytes = buildClass("com/example/NoTargets") { mv ->
            mv.visitCode()
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(0, 1)
            mv.visitEnd()
        }

        val out = transform.tryTransform(bytes, "com/example/NoTargets.class")
        assertNull(
            "classes with no target call sites MUST be passthrough (null) so " +
                "the caller writes the original bytes back byte-for-byte",
            out
        )
    }

    @Test
    fun `class that calls OkHttpClient$Builder#build is rewritten`() {
        val bytes = buildClass("com/example/OkHttpCaller") { mv ->
            mv.visitCode()
            // Receiver: push a null Builder to keep bytecode legal for
            // our purposes. This class will never be loaded by a JVM;
            // we only care that ASM's visitMethodInsn is triggered.
            mv.visitInsn(Opcodes.ACONST_NULL)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                "okhttp3/OkHttpClient\$Builder",
                "build",
                "()Lokhttp3/OkHttpClient;",
                false
            )
            mv.visitInsn(Opcodes.POP)
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(1, 1)
            mv.visitEnd()
        }

        val out = transform.tryTransform(bytes, "com/example/OkHttpCaller.class")
        assertNotNull(
            "classes calling OkHttpClient.Builder.build() must be rewritten",
            out
        )
        assertTrue(
            "rewritten class should carry the NetScopeInterceptorInjector reference",
            String(out!!).contains("NetScopeInterceptorInjector")
        )
    }

    @Test
    fun `class that calls HttpURLConnection#getInputStream is rewritten`() {
        val bytes = buildClass("com/example/UrlCaller") { mv ->
            mv.visitCode()
            mv.visitInsn(Opcodes.ACONST_NULL)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                "java/net/HttpURLConnection",
                "getInputStream",
                "()Ljava/io/InputStream;",
                false
            )
            mv.visitInsn(Opcodes.POP)
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(1, 1)
            mv.visitEnd()
        }

        val out = transform.tryTransform(bytes, "com/example/UrlCaller.class")
        assertNotNull("HttpURLConnection.getInputStream call must be rewritten", out)
    }

    @Test
    fun `class with unrelated INVOKEVIRTUAL is NOT rewritten`() {
        // Reproduces the shape of NavigationService$3.getMapAge on Denali
        // that tripped D8 in v2.0.1 — a class that has plenty of
        // INVOKEVIRTUAL to other types but NONE of our targets.
        val bytes = buildClass("com/example/OtherCalls") { mv ->
            mv.visitCode()
            mv.visitLdcInsn("hello")
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                "java/lang/String", "length", "()I", false
            )
            mv.visitInsn(Opcodes.POP)
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(1, 1)
            mv.visitEnd()
        }

        val out = transform.tryTransform(bytes, "com/example/OtherCalls.class")
        assertNull("unrelated INVOKEVIRTUAL must not trigger rewrite", out)
    }

    @Test
    fun `skipped packages short-circuit before the prefilter runs`() {
        // An okhttp3/ class that happens to call build() on itself — we
        // must still skip it. This matches the historical shouldSkipClass
        // contract and keeps v2.0.2 backward-compatible.
        val bytes = buildClass("okhttp3/SomeInternal") { mv ->
            mv.visitCode()
            mv.visitInsn(Opcodes.ACONST_NULL)
            mv.visitMethodInsn(
                Opcodes.INVOKEVIRTUAL,
                "okhttp3/OkHttpClient\$Builder",
                "build",
                "()Lokhttp3/OkHttpClient;",
                false
            )
            mv.visitInsn(Opcodes.POP)
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(1, 1)
            mv.visitEnd()
        }

        val out = transform.tryTransform(bytes, "okhttp3/SomeInternal.class")
        assertNull("classes in skipped packages must be passthrough even if they contain targets", out)
    }

    /** Build a minimal class with one public static void foo() method. */
    private fun buildClass(internalName: String, body: (MethodVisitor) -> Unit): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC,
            internalName,
            null,
            "java/lang/Object",
            null
        )
        val mv = cw.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "foo",
            "()V",
            null,
            null
        )
        body(mv)
        cw.visitEnd()
        return cw.toByteArray()
    }

    @Test
    fun `synthetic class fixture is a valid class file (sanity)`() {
        val bytes = buildClass("com/example/Sanity") { mv ->
            mv.visitCode()
            mv.visitInsn(Opcodes.RETURN)
            mv.visitMaxs(0, 1)
            mv.visitEnd()
        }
        assertEquals(0xCA.toByte(), bytes[0])
        assertEquals(0xFE.toByte(), bytes[1])
    }
}
