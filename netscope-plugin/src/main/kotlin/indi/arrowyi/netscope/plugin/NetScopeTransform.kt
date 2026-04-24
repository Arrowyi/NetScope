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
import org.objectweb.asm.ClassVisitor
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

    internal fun tryTransform(bytes: ByteArray, name: String): ByteArray? {
        // module-info.class and similar — skip.
        if (bytes.size < 4 || bytes[0] != 0xCA.toByte() || bytes[1] != 0xFE.toByte()) {
            return null
        }
        val reader = try { ClassReader(bytes) } catch (_: Throwable) { return null }
        val className = reader.className
        if (shouldSkipClass(className, name)) return null

        // Prefilter: skip the ASM round-trip entirely for classes that do
        // not contain any of our three target call sites. Without this,
        // EVERY class in the build went through a ClassReader -> visitor
        // chain -> ClassWriter cycle, which is not byte-for-byte identical
        // to the input (ASM reorders constant pool entries, re-emits
        // attributes etc.). In practice this exposed D8 to classes that
        // compiled fine but could not dex after the round-trip. The
        // prefilter takes us from ~100% of classes rewritten to just the
        // handful that actually need it.
        if (!needsRewrite(reader)) return null

        // COMPUTE_MAXS: recompute maxStack / maxLocals only, preserve the
        // existing StackMapTable. Safe for our three instrumenters because
        // none of them introduce new branch targets or change the types
        // that cross existing frame boundaries — they only insert
        // straight-line INVOKESTATIC wrappers. Using COMPUTE_FRAMES would
        // force ASM into getCommonSuperClass(), which tries to
        // Class.forName() arbitrary business types via the plugin's
        // classloader — those types aren't visible there, and a wrong
        // answer corrupts the StackMapTable and trips D8 later
        // ("Invalid descriptor char 'N'").
        val writer = ClassWriter(reader, ClassWriter.COMPUTE_MAXS)

        // Chain the instrumenters. Each one is a ClassVisitor that
        // delegates to the next; the tail is the writer.
        var visitor: ClassVisitor = writer
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

    /**
     * Readonly scan: returns true only if the class contains at least one
     * `INVOKEVIRTUAL` to a method that one of our three instrumenters
     * cares about. We walk with `SKIP_DEBUG | SKIP_FRAMES` and early-exit
     * the first match (via a thrown sentinel caught here) so the worst
     * case is a single method-body walk per class. For the common case
     * of a class with no target calls, this is cheap.
     */
    private fun needsRewrite(reader: ClassReader): Boolean {
        val detector = TargetDetector()
        return try {
            reader.accept(detector, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            false
        } catch (_: TargetDetector.Found) {
            true
        }
    }

    private class TargetDetector : ClassVisitor(Opcodes.ASM9) {
        object Found : RuntimeException() {
            private fun readResolve(): Any = Found
            override fun fillInStackTrace(): Throwable = this
        }

        override fun visitMethod(
            access: Int, name: String?, descriptor: String?,
            signature: String?, exceptions: Array<out String>?
        ): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
            override fun visitMethodInsn(
                opcode: Int, owner: String?, methodName: String?,
                methodDescriptor: String?, isInterface: Boolean
            ) {
                if (opcode == Opcodes.INVOKEVIRTUAL && isTarget(owner, methodName, methodDescriptor)) {
                    throw Found
                }
            }
        }

        private fun isTarget(owner: String?, name: String?, desc: String?): Boolean {
            if (owner == null || name == null || desc == null) return false
            // OkHttpClient.Builder#build()Lokhttp3/OkHttpClient;
            if (owner == "okhttp3/OkHttpClient\$Builder"
                && name == "build"
                && desc == "()Lokhttp3/OkHttpClient;"
            ) return true
            // OkHttpClient#newWebSocket(Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;
            if (owner == "okhttp3/OkHttpClient"
                && name == "newWebSocket"
                && desc == "(Lokhttp3/Request;Lokhttp3/WebSocketListener;)Lokhttp3/WebSocket;"
            ) return true
            // URLConnection / HttpURLConnection / HttpsURLConnection
            // getInputStream()Ljava/io/InputStream; and
            // getOutputStream()Ljava/io/OutputStream;.
            val urlOwner = owner == "java/net/URLConnection"
                || owner == "java/net/HttpURLConnection"
                || owner == "javax/net/ssl/HttpsURLConnection"
            if (urlOwner && name == "getInputStream" && desc == "()Ljava/io/InputStream;") return true
            if (urlOwner && name == "getOutputStream" && desc == "()Ljava/io/OutputStream;") return true
            return false
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
