package indi.arrowyi.netscope.plugin

import org.gradle.api.logging.Logger
import org.gradle.api.logging.Logging
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream

/**
 * v2.0.3 cross-scope duplicate-class dedupe.
 *
 * Reproduces the Denali shape: two jars each contain a class named
 * `com/telenav/auto/dr/BuildConfig` — one from a local `:dr` module,
 * one from a vendor `:dr` AAR with the same manifest `package`.
 *
 * The Transform-internal [NetScopeTransform.transformJarWithDedupe]
 * must emit the class from the FIRST jar (simulating the higher-
 * priority PROJECT / SUB_PROJECTS scope) and DROP it from the second
 * jar (simulating EXTERNAL_LIBRARIES scope), matching what AGP's
 * baseline DexMergingTask would have done under scope-split routing.
 * Without this, D8 trips on `Type ... is defined multiple times`.
 */
class NetScopeTransformDedupeTest {

    @Rule
    @JvmField
    val tempFolder = TemporaryFolder()

    private val log: Logger = Logging.getLogger("NetScopeTransformDedupeTest")
    private val transform = NetScopeTransform(log)

    @Test
    fun `duplicate class across two jars keeps only the first-seen`() {
        val jarA = makeJarWithClasses(
            name = "a.jar",
            classes = mapOf(
                "com/foo/BuildConfig" to minimalClass("com/foo/BuildConfig"),
                "com/foo/Other" to minimalClass("com/foo/Other")
            )
        )
        val jarB = makeJarWithClasses(
            name = "b.jar",
            classes = mapOf(
                "com/foo/BuildConfig" to minimalClass("com/foo/BuildConfig"), // duplicate
                "com/foo/UniqueToB" to minimalClass("com/foo/UniqueToB")
            )
        )
        val outA = tempFolder.newFile("out_a.jar")
        val outB = tempFolder.newFile("out_b.jar")

        val seen = HashSet<String>()
        // Process jarA FIRST — it simulates the higher-priority scope.
        transform.transformJarWithDedupe(jarA, outA, seen)
        transform.transformJarWithDedupe(jarB, outB, seen)

        val entriesA = readClassEntries(outA)
        val entriesB = readClassEntries(outB)

        assertTrue(
            "BuildConfig from the first (higher-priority) jar must survive",
            "com/foo/BuildConfig.class" in entriesA
        )
        assertTrue("first jar's unique class survives", "com/foo/Other.class" in entriesA)

        assertFalse(
            "BuildConfig from the second (lower-priority) jar must be dropped",
            "com/foo/BuildConfig.class" in entriesB
        )
        assertTrue(
            "second jar's unique-to-it class still survives (no spurious drops)",
            "com/foo/UniqueToB.class" in entriesB
        )
    }

    @Test
    fun `non-class entries are always copied even if the jar name is common`() {
        val jarA = makeJarWithEntries(
            name = "a.jar",
            entries = listOf(
                "com/foo/BuildConfig.class" to minimalClass("com/foo/BuildConfig"),
                "META-INF/MANIFEST.MF" to "Manifest-Version: 1.0\n".toByteArray(),
                "resource.txt" to "hello".toByteArray()
            )
        )
        val outA = tempFolder.newFile("out_a.jar")
        transform.transformJarWithDedupe(jarA, outA, HashSet())

        val allEntries = readAllEntries(outA)
        assertTrue("class entry present", "com/foo/BuildConfig.class" in allEntries)
        assertTrue("manifest passes through", "META-INF/MANIFEST.MF" in allEntries)
        assertTrue("arbitrary resource passes through", "resource.txt" in allEntries)
    }

    @Test
    fun `same jar processed twice does not double-emit`() {
        val jar = makeJarWithClasses(
            name = "x.jar",
            classes = mapOf("com/foo/X" to minimalClass("com/foo/X"))
        )
        val out1 = tempFolder.newFile("x_out1.jar")
        val out2 = tempFolder.newFile("x_out2.jar")

        val seen = HashSet<String>()
        transform.transformJarWithDedupe(jar, out1, seen)
        transform.transformJarWithDedupe(jar, out2, seen)

        assertTrue("first emission keeps the class", "com/foo/X.class" in readClassEntries(out1))
        assertFalse("second emission drops the class as already seen", "com/foo/X.class" in readClassEntries(out2))
    }

    // ─── Helpers ───

    private fun minimalClass(internalName: String): ByteArray {
        val cw = ClassWriter(0)
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "foo", "()V", null, null)
        mv.visitCode(); mv.visitInsn(Opcodes.RETURN); mv.visitMaxs(0, 0); mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun makeJarWithClasses(name: String, classes: Map<String, ByteArray>): File =
        makeJarWithEntries(
            name = name,
            entries = classes.map { (internal, bytes) -> "$internal.class" to bytes }
        )

    private fun makeJarWithEntries(name: String, entries: List<Pair<String, ByteArray>>): File {
        val f = tempFolder.newFile(name)
        JarOutputStream(FileOutputStream(f)).use { jout ->
            for ((entryName, body) in entries) {
                jout.putNextEntry(JarEntry(entryName))
                jout.write(body)
                jout.closeEntry()
            }
        }
        return f
    }

    private fun readClassEntries(jar: File): Set<String> =
        readAllEntries(jar).filterTo(mutableSetOf()) { it.endsWith(".class") }

    private fun readAllEntries(jar: File): Set<String> {
        val out = mutableSetOf<String>()
        JarInputStream(FileInputStream(jar)).use { jin ->
            var e: JarEntry? = jin.nextJarEntry
            while (e != null) {
                out.add(e.name)
                e = jin.nextJarEntry
            }
        }
        return out
    }

    @Test
    fun `entry count sanity (helper fixture produces real jars)`() {
        val j = makeJarWithClasses(
            name = "sanity.jar",
            classes = mapOf("a/B" to minimalClass("a/B"), "c/D" to minimalClass("c/D"))
        )
        assertEquals(setOf("a/B.class", "c/D.class"), readClassEntries(j))
    }
}
