package indi.arrowyi.netscope.plugin.instrumenter

import org.gradle.api.logging.Logger
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Rewrites every call to `okhttp3.OkHttpClient$Builder#build()` so that
 * the builder is first passed through
 * `NetScopeInterceptorInjector.addIfMissing(builder)` — which
 * idempotently appends [NetScopeInterceptor] if not present — and then
 * the original `build()` is invoked.
 *
 * Why at call-sites rather than at OkHttp's own `build()`: we must NOT
 * modify bytecode inside the `okhttp3/` package (the Transform's skip
 * list enforces this). Instrumenting call sites is also what lets us
 * leave any host code that manually adds our interceptor alone (the
 * injector's `addIfMissing` check).
 *
 * Transformation (pseudo-Java):
 * ```
 *   client = builder.build();
 * ```
 * becomes
 * ```
 *   client = NetScopeInterceptorInjector.addIfMissing(builder).build();
 * ```
 *
 * Bytecode:
 *   Before:
 *       INVOKEVIRTUAL okhttp3/OkHttpClient$Builder.build ()Lokhttp3/OkHttpClient;
 *   After:
 *       INVOKESTATIC  .../NetScopeInterceptorInjector.addIfMissing
 *                     (Lokhttp3/OkHttpClient$Builder;)Lokhttp3/OkHttpClient$Builder;
 *       INVOKEVIRTUAL okhttp3/OkHttpClient$Builder.build ()Lokhttp3/OkHttpClient;
 */
internal class OkHttpBuilderInstrumenter(
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
                if (opcode == Opcodes.INVOKEVIRTUAL
                    && ownerIn == OKHTTP_BUILDER
                    && nameIn == "build"
                    && descriptorIn == "()Lokhttp3/OkHttpClient;"
                ) {
                    // Stack top at this point: the Builder instance.
                    // Insert INVOKESTATIC addIfMissing(Builder)Builder
                    // to replace it with the injected Builder.
                    super.visitMethodInsn(
                        Opcodes.INVOKESTATIC,
                        INJECTOR,
                        "addIfMissing",
                        "(L$OKHTTP_BUILDER;)L$OKHTTP_BUILDER;",
                        false
                    )
                    log.info("[NetScope] injected interceptor at $owningClass.$name")
                }
                super.visitMethodInsn(opcode, ownerIn, nameIn, descriptorIn, isInterface)
            }
        }
    }

    companion object {
        private const val OKHTTP_BUILDER = "okhttp3/OkHttpClient\$Builder"
        private const val INJECTOR =
            "indi/arrowyi/netscope/sdk/integration/NetScopeInterceptorInjector"
    }
}
