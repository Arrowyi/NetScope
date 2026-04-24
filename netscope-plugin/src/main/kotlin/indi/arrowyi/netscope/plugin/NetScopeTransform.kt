package indi.arrowyi.netscope.plugin

import com.android.build.api.transform.DirectoryInput
import com.android.build.api.transform.Format
import com.android.build.api.transform.JarInput
import com.android.build.api.transform.QualifiedContent
import com.android.build.api.transform.Status
import com.android.build.api.transform.Transform
import com.android.build.api.transform.TransformInvocation
import com.android.build.gradle.internal.pipeline.TransformManager
import indi.arrowyi.netscope.plugin.instrumenter.OkHttpBuilderInstrumenter
import indi.arrowyi.netscope.plugin.instrumenter.OkHttpWebSocketInstrumenter
import indi.arrowyi.netscope.plugin.instrumenter.UrlConnectionInstrumenter
import org.gradle.api.logging.Logger
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream

/**
 * Legacy-API (`com.android.build.api.transform.Transform`) Gradle
 * Transform that visits every `.class` file in the project + sub-projects
 * + external library jars and applies NetScope's instrumenters.
 *
 * Incremental: honours the `incremental` flag and per-input
 * `Status`, so re-builds only touch changed files.
 *
 * Scope choice: CLASSES content + `PROJECT | SUB_PROJECTS | EXTERNAL_LIBRARIES`
 * so an OkHttpClient created inside a vendor AAR is also instrumented.
 *
 * AspectJ coexistence: `shouldSkipClass()` early-outs on any class name
 * containing `$ajc$` or ending with `$AjcClosure`. Apply this plugin
 * AFTER the AspectJ plugin in your `build.gradle`.
 */
class NetScopeTransform(private val log: Logger) : Transform() {

    override fun getName(): String = "netscope"

    override fun getInputTypes(): MutableSet<QualifiedContent.ContentType> =
        TransformManager.CONTENT_CLASS

    override fun getScopes(): MutableSet<in QualifiedContent.Scope> =
        TransformManager.SCOPE_FULL_PROJECT

    override fun isIncremental(): Boolean = true

    override fun transform(invocation: TransformInvocation) {
        val outputProvider = invocation.outputProvider ?: return
        if (!invocation.isIncremental) outputProvider.deleteAll()

        for (input in invocation.inputs) {
            for (dirInput in input.directoryInputs) {
                handleDirectoryInput(dirInput, outputProvider, invocation.isIncremental)
            }
            for (jarInput in input.jarInputs) {
                handleJarInput(jarInput, outputProvider, invocation.isIncremental)
            }
        }
    }

    // ─── Directory inputs (module class output) ───────────────────────────

    private fun handleDirectoryInput(
        dirInput: DirectoryInput,
        outputProvider: com.android.build.api.transform.TransformOutputProvider,
        incremental: Boolean
    ) {
        val dest: File = outputProvider.getContentLocation(
            dirInput.name, dirInput.contentTypes, dirInput.scopes, Format.DIRECTORY
        )
        if (incremental) {
            val changed = dirInput.changedFiles
            if (changed.isEmpty()) return
            for ((file, status) in changed) {
                val relative = dirInput.file.toPath().relativize(file.toPath()).toString()
                val outFile = File(dest, relative)
                when (status) {
                    Status.NOTCHANGED -> {}
                    Status.REMOVED -> outFile.delete()
                    Status.ADDED, Status.CHANGED -> {
                        outFile.parentFile?.mkdirs()
                        writeTransformed(file, outFile)
                    }
                    else -> {}
                }
            }
        } else {
            copyAndTransformDir(dirInput.file, dest)
        }
    }

    private fun copyAndTransformDir(src: File, dst: File) {
        if (!src.isDirectory) return
        src.walkTopDown().filter { it.isFile }.forEach { file ->
            val relative = src.toPath().relativize(file.toPath()).toString()
            val outFile = File(dst, relative)
            outFile.parentFile?.mkdirs()
            writeTransformed(file, outFile)
        }
    }

    private fun writeTransformed(input: File, output: File) {
        if (!input.name.endsWith(".class")) {
            input.copyTo(output, overwrite = true)
            return
        }
        val bytes = FileInputStream(input).use { it.readBytes() }
        val transformed = tryTransform(bytes, input.name) ?: bytes
        FileOutputStream(output).use { it.write(transformed) }
    }

    // ─── Jar inputs (external libraries + sub-projects) ────────────────────

    private fun handleJarInput(
        jarInput: JarInput,
        outputProvider: com.android.build.api.transform.TransformOutputProvider,
        incremental: Boolean
    ) {
        val dest: File = outputProvider.getContentLocation(
            jarInput.name, jarInput.contentTypes, jarInput.scopes, Format.JAR
        )
        if (incremental) {
            when (jarInput.status) {
                Status.NOTCHANGED -> return
                Status.REMOVED -> { dest.delete(); return }
                else -> {}
            }
        }
        transformJar(jarInput.file, dest)
    }

    private fun transformJar(inputJar: File, outputJar: File) {
        outputJar.parentFile?.mkdirs()
        JarInputStream(FileInputStream(inputJar)).use { jin ->
            JarOutputStream(FileOutputStream(outputJar)).use { jout ->
                var entry: JarEntry? = jin.nextJarEntry
                while (entry != null) {
                    val name = entry.name
                    jout.putNextEntry(JarEntry(name))
                    val body = jin.readBytes()
                    val outBytes = if (name.endsWith(".class")) {
                        tryTransform(body, name) ?: body
                    } else body
                    jout.write(outBytes)
                    jout.closeEntry()
                    entry = jin.nextJarEntry
                }
            }
        }
    }

    // ─── ASM pipeline ─────────────────────────────────────────────────────

    private fun tryTransform(bytes: ByteArray, name: String): ByteArray? {
        // module-info.class and similar — skip.
        if (bytes.size < 4 || bytes[0] != 0xCA.toByte() || bytes[1] != 0xFE.toByte()) {
            return null
        }
        val reader = try { ClassReader(bytes) } catch (_: Throwable) { return null }
        val className = reader.className
        if (shouldSkipClass(className, name)) return null

        // COMPUTE_FRAMES: mandatory because our instrumenters insert
        // instructions that reshape the operand stack mid-method. Without
        // frame recomputation, the class file's existing stack map would
        // be out of sync with the new bytecode and the JVM verifier would
        // reject the class.
        //
        // getCommonSuperClass is overridden to return java/lang/Object on
        // ClassNotFoundException. Rationale: at build time we don't have
        // access to the application's own ClassLoader, so resolving
        // arbitrary user classes to compute their superclass chain will
        // fail; ASM's default impl then throws. Falling back to Object is
        // safe for frame computation purposes — it's a superclass of
        // everything, so the computed frames will be conservative but
        // correct.
        val writer = object : ClassWriter(reader, COMPUTE_FRAMES) {
            override fun getCommonSuperClass(type1: String, type2: String): String {
                return try {
                    super.getCommonSuperClass(type1, type2)
                } catch (_: Throwable) {
                    "java/lang/Object"
                }
            }
        }

        // Chain the instrumenters. Each one is a ClassVisitor that
        // delegates to the next; the tail is the writer.
        var visitor: org.objectweb.asm.ClassVisitor = writer
        visitor = OkHttpWebSocketInstrumenter(Opcodes.ASM9, visitor, className, log)
        visitor = UrlConnectionInstrumenter(Opcodes.ASM9, visitor, className, log)
        visitor = OkHttpBuilderInstrumenter(Opcodes.ASM9, visitor, className, log)

        return try {
            reader.accept(visitor, 0)
            writer.toByteArray()
        } catch (t: Throwable) {
            log.warn("[NetScope] skip ${className}: ${t.message}")
            null
        }
    }

    private fun shouldSkipClass(internalName: String?, jarEntry: String): Boolean {
        if (internalName == null) return true

        // AspectJ coexistence — leave AspectJ-synthesized classes alone.
        if (internalName.contains("\$ajc\$")) return true
        if (internalName.endsWith("\$AjcClosure")) return true

        // Skip our own runtime to prevent self-instrumentation loops.
        if (internalName.startsWith("indi/arrowyi/netscope/sdk/")) return true
        if (internalName.startsWith("indi/arrowyi/netscope/plugin/")) return true

        // Skip the instrumented libraries' own classes — OkHttp's
        // internals include OkHttpClient.Builder.build(); if we rewrote
        // build() calls INSIDE the OkHttp jar itself, OkHttp's own
        // internal construction paths would loop. Also we don't want to
        // rewrite URL calls inside java.* (which won't be in user jars
        // anyway, but be explicit).
        if (internalName.startsWith("okhttp3/")) return true
        if (internalName.startsWith("okio/")) return true
        if (internalName.startsWith("kotlin/")) return true
        if (internalName.startsWith("kotlinx/")) return true
        if (internalName.startsWith("java/")) return true
        if (internalName.startsWith("javax/")) return true
        if (internalName.startsWith("android/")) return true
        if (internalName.startsWith("androidx/")) return true
        if (internalName.startsWith("com/android/")) return true
        if (internalName.startsWith("com/google/android/")) return true
        if (internalName.startsWith("dalvik/")) return true

        // Skip modular / non-class jar entries.
        if (jarEntry.endsWith("module-info.class") || jarEntry.contains("META-INF/")) return true

        return false
    }
}

/**
 * Small convenience used by multiple instrumenters to inject a simple
 * `INVOKESTATIC` call that replaces the top-of-stack value with the
 * wrapped version returned by a NetScope helper.
 */
internal fun MethodVisitor.invokeStaticWrap(owner: String, name: String, descriptor: String) {
    visitMethodInsn(Opcodes.INVOKESTATIC, owner, name, descriptor, false)
}
