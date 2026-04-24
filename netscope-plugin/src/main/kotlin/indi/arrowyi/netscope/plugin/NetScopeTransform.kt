package indi.arrowyi.netscope.plugin

import com.android.build.api.transform.DirectoryInput
import com.android.build.api.transform.Format
import com.android.build.api.transform.JarInput
import com.android.build.api.transform.QualifiedContent
import com.android.build.api.transform.Transform
import com.android.build.api.transform.TransformInvocation
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
 * **Scope choice (v2.0.3+):** main scope is `{PROJECT, SUB_PROJECTS,
 * EXTERNAL_LIBRARIES}`, so OkHttp / URL / WebSocket call sites inside
 * vendor AARs (e.g. an HMI's `:search` module shipped as a prebuilt
 * AAR) are also rewritten and contribute to `getApiStats()`.
 *
 * **Cross-scope duplicate-class dedupe (v2.0.3+):** there is a known
 * AGP 4.x trap when a Transform's main scope includes
 * `EXTERNAL_LIBRARIES`: AGP funnels every input into
 * `mixed_scope_dex_archive/`, and the downstream `DexMergingTask`
 * runs a single merge invocation on the whole mixed bucket. This
 * collapses the per-scope dedupe mechanism that normally lets
 * cross-module same-named classes (e.g. a local `:dr` module AND a
 * vendor AAR that both declare `package="com.foo.dr"` in their
 * manifest, so AGP synthesises `com.foo.dr.BuildConfig` twice)
 * coexist, producing `D8: Type ... is defined multiple times`. This
 * hit HMI's Denali in v2.0.2.
 *
 * The fix is to reproduce AGP's scope-priority dedupe *inside* the
 * Transform: we process inputs in order `PROJECT > SUB_PROJECTS >
 * EXTERNAL_LIBRARIES` and track internal class names we have already
 * emitted. When a later input carries a class name we've already
 * seen from a higher-priority scope, we drop it. This matches the
 * behaviour AGP would have had under its default scope-split pipeline.
 *
 * Because dedupe relies on a global "seen classes" set built during
 * the current invocation, this Transform is **non-incremental** (full
 * rebuild every time). An incremental variant would require
 * persisting the seen-set across runs and re-resolving when sources
 * change — the complexity is not worth it for a Transform whose
 * per-class hot path is dominated by the cheap [needsRewrite]
 * prefilter.
 *
 * AspectJ coexistence: [shouldSkipClass] early-outs on any class
 * name containing `$ajc$` or ending with `$AjcClosure`. Apply this
 * plugin AFTER the AspectJ plugin in your `build.gradle`.
 */
class NetScopeTransform(private val log: Logger) : Transform() {

    override fun getName(): String = "netscope"

    override fun getInputTypes(): MutableSet<QualifiedContent.ContentType> =
        mutableSetOf(QualifiedContent.DefaultContentType.CLASSES)

    /**
     * v2.0.3: the full triad `{PROJECT, SUB_PROJECTS, EXTERNAL_LIBRARIES}`,
     * spelled out so we don't have to depend on a `TransformManager`
     * internal constant. Cross-scope same-named classes are handled by
     * the dedupe logic in [transform], not by restricting scope.
     */
    override fun getScopes(): MutableSet<in QualifiedContent.Scope> =
        mutableSetOf(
            QualifiedContent.Scope.PROJECT,
            QualifiedContent.Scope.SUB_PROJECTS,
            QualifiedContent.Scope.EXTERNAL_LIBRARIES
        )

    /**
     * v2.0.3: non-incremental. Dedupe needs a global seen-set built
     * from every input in the current invocation, which is not
     * correct across partial builds.
     */
    override fun isIncremental(): Boolean = false

    override fun transform(invocation: TransformInvocation) {
        val outputProvider = invocation.outputProvider ?: return
        outputProvider.deleteAll()

        // Collect every input, then process in scope-priority order so
        // that higher-priority scopes claim disputed class names first.
        val allDirInputs = mutableListOf<DirectoryInput>()
        val allJarInputs = mutableListOf<JarInput>()
        for (input in invocation.inputs) {
            allDirInputs.addAll(input.directoryInputs)
            allJarInputs.addAll(input.jarInputs)
        }
        val sortedDirInputs = allDirInputs.sortedBy { scopePriority(it.scopes) }
        val sortedJarInputs = allJarInputs.sortedBy { scopePriority(it.scopes) }

        // `seenClasses` holds every internal class name we have already
        // emitted to any output in this invocation. A later input whose
        // entry collides (same internal name) is dropped — the
        // higher-priority scope already wrote its copy.
        val seenClasses = HashSet<String>()

        for (dirInput in sortedDirInputs) {
            handleDirectoryInput(dirInput, outputProvider, seenClasses)
        }
        for (jarInput in sortedJarInputs) {
            handleJarInput(jarInput, outputProvider, seenClasses)
        }
    }

    /**
     * Scope priority used for cross-scope duplicate-class dedupe.
     * Lower number = higher priority (claims the name first). This
     * mirrors AGP's baseline DexMergingTask behaviour: local code
     * wins over sub-project jars, which win over external libraries.
     */
    internal fun scopePriority(scopes: Set<*>): Int = when {
        scopes.contains(QualifiedContent.Scope.PROJECT) -> 0
        scopes.contains(QualifiedContent.Scope.SUB_PROJECTS) -> 1
        scopes.contains(QualifiedContent.Scope.EXTERNAL_LIBRARIES) -> 2
        else -> 3
    }

    // ─── Directory inputs (module class output) ───────────────────────────

    private fun handleDirectoryInput(
        dirInput: DirectoryInput,
        outputProvider: com.android.build.api.transform.TransformOutputProvider,
        seenClasses: MutableSet<String>
    ) {
        val dest: File = outputProvider.getContentLocation(
            dirInput.name, dirInput.contentTypes, dirInput.scopes, Format.DIRECTORY
        )
        if (!dirInput.file.isDirectory) return
        dirInput.file.walkTopDown().filter { it.isFile }.forEach { file ->
            val relative = dirInput.file.toPath().relativize(file.toPath()).toString()
            val outFile = File(dest, relative)
            writeTransformedWithDedupe(file, outFile, seenClasses)
        }
    }

    private fun writeTransformedWithDedupe(
        input: File,
        output: File,
        seenClasses: MutableSet<String>
    ) {
        if (!input.name.endsWith(".class")) {
            output.parentFile?.mkdirs()
            input.copyTo(output, overwrite = true)
            return
        }
        val bytes = FileInputStream(input).use { it.readBytes() }
        val internalName = readInternalName(bytes)
        if (internalName != null && !seenClasses.add(internalName)) {
            log.info("[NetScope] dedupe: skip duplicate class {} (dir input {})", internalName, input)
            return
        }
        val transformed = tryTransform(bytes, input.name) ?: bytes
        output.parentFile?.mkdirs()
        FileOutputStream(output).use { it.write(transformed) }
    }

    // ─── Jar inputs (external libraries + sub-projects) ────────────────────

    private fun handleJarInput(
        jarInput: JarInput,
        outputProvider: com.android.build.api.transform.TransformOutputProvider,
        seenClasses: MutableSet<String>
    ) {
        val dest: File = outputProvider.getContentLocation(
            jarInput.name, jarInput.contentTypes, jarInput.scopes, Format.JAR
        )
        transformJarWithDedupe(jarInput.file, dest, seenClasses)
    }

    /**
     * Copy `inputJar` to `outputJar`, rewriting class bytes via
     * [tryTransform] and **skipping** any class entry whose internal
     * name is already present in [seenClasses]. Non-class entries are
     * copied as-is. Duplicate-class skip-writes are logged at `info`
     * level for diagnostics.
     *
     * Internal visibility so unit tests can exercise the dedupe path
     * without spinning up a full `TransformInvocation`.
     */
    internal fun transformJarWithDedupe(
        inputJar: File,
        outputJar: File,
        seenClasses: MutableSet<String>
    ) {
        outputJar.parentFile?.mkdirs()
        JarInputStream(FileInputStream(inputJar)).use { jin ->
            JarOutputStream(FileOutputStream(outputJar)).use { jout ->
                var entry: JarEntry? = jin.nextJarEntry
                while (entry != null) {
                    val name = entry.name
                    val body = jin.readBytes()

                    if (name.endsWith(".class")) {
                        val internalName = readInternalName(body)
                        if (internalName != null && !seenClasses.add(internalName)) {
                            log.info(
                                "[NetScope] dedupe: skip duplicate class {} (jar {})",
                                internalName, inputJar
                            )
                            entry = jin.nextJarEntry
                            continue
                        }
                        val outBytes = tryTransform(body, name) ?: body
                        jout.putNextEntry(JarEntry(name))
                        jout.write(outBytes)
                        jout.closeEntry()
                    } else {
                        jout.putNextEntry(JarEntry(name))
                        jout.write(body)
                        jout.closeEntry()
                    }
                    entry = jin.nextJarEntry
                }
            }
        }
    }

    /**
     * Read a class file's internal name cheaply via `ClassReader`.
     * Returns `null` for non-class byte streams (e.g. short headers,
     * corrupt entries) — the caller treats `null` as "not a class we
     * can dedupe on" and keeps the entry.
     */
    private fun readInternalName(bytes: ByteArray): String? {
        if (bytes.size < 4 || bytes[0] != 0xCA.toByte() || bytes[1] != 0xFE.toByte()) return null
        return try { ClassReader(bytes).className } catch (_: Throwable) { null }
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
