package indi.arrowyi.netscope.plugin

import com.android.build.api.transform.QualifiedContent
import org.gradle.api.logging.Logger
import org.gradle.api.logging.Logging
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * v2.0.3 scope + priority contract.
 *
 * HMI's Denali 2026-04-24 investigation showed that:
 *   - Layer B must cover external AAR OkHttp / URL / WebSocket call
 *     sites (HMIs have large vendor AARs like `:search` that dominate
 *     their network traffic).
 *   - v2.0.2's `SCOPE_FULL_PROJECT` + naive passthrough triggered
 *     `D8: Type com.telenav.auto.dr.BuildConfig is defined multiple
 *     times` because the Transform collapsed per-scope dedupe into
 *     `mixed_scope_dex_archive/`.
 *
 * v2.0.3 answers both:
 *   - Keep the main scope wide (`{PROJECT, SUB_PROJECTS,
 *     EXTERNAL_LIBRARIES}`) so vendor AAR call sites ARE rewritten.
 *   - Implement scope-priority dedupe inside the Transform so
 *     higher-priority scopes claim disputed class names first — this
 *     mirrors AGP's baseline DexMergingTask behaviour.
 *
 * This test is cheap insurance against either contract regressing.
 */
class NetScopeTransformScopeTest {

    private val log: Logger = Logging.getLogger("NetScopeTransformScopeTest")
    private val transform = NetScopeTransform(log)

    @Test
    fun `main scope includes PROJECT, SUB_PROJECTS and EXTERNAL_LIBRARIES`() {
        val scopes = transform.scopes
        assertEquals(
            "v2.0.3: main scope must include all three so vendor AARs are instrumented",
            3,
            scopes.size
        )
        assertTrue(scopes.contains(QualifiedContent.Scope.PROJECT))
        assertTrue(scopes.contains(QualifiedContent.Scope.SUB_PROJECTS))
        assertTrue(
            "v2.0.3 regression guard: EXTERNAL_LIBRARIES MUST be in the main scope. " +
                "Dropping it would mean vendor AAR OkHttp / URL / WebSocket call " +
                "sites don't contribute to Layer B (per-domain stats), which breaks " +
                "HMIs whose traffic is dominated by shipped-as-AAR modules (e.g. :search).",
            scopes.contains(QualifiedContent.Scope.EXTERNAL_LIBRARIES)
        )
    }

    @Test
    fun `scope priority is PROJECT lower than SUB_PROJECTS lower than EXTERNAL_LIBRARIES`() {
        val p = transform.scopePriority(mutableSetOf(QualifiedContent.Scope.PROJECT))
        val s = transform.scopePriority(mutableSetOf(QualifiedContent.Scope.SUB_PROJECTS))
        val e = transform.scopePriority(mutableSetOf(QualifiedContent.Scope.EXTERNAL_LIBRARIES))

        assertTrue("PROJECT must have strictly higher priority than SUB_PROJECTS", p < s)
        assertTrue("SUB_PROJECTS must have strictly higher priority than EXTERNAL_LIBRARIES", s < e)
    }

    @Test
    fun `transform is non-incremental`() {
        assertFalse(
            "v2.0.3: dedupe needs a fresh seen-set every run; a naive incremental " +
                "run would not re-visit unchanged jars and would emit duplicate classes",
            transform.isIncremental
        )
    }

    @Test
    fun `input types is CLASSES only`() {
        val types = transform.inputTypes
        assertEquals(1, types.size)
        assertTrue(types.contains(QualifiedContent.DefaultContentType.CLASSES))
    }
}
