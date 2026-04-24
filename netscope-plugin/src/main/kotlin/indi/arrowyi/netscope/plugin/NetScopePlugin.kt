package indi.arrowyi.netscope.plugin

import com.android.build.gradle.AppExtension
import com.android.build.gradle.LibraryExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.logging.Logger

/**
 * NetScope AOP Gradle plugin.
 *
 * Apply with `plugins { id 'indi.arrowyi.netscope' }` in any Android
 * application or library module. Auto-registers [NetScopeTransform] on
 * whichever AGP extension is present (`AppExtension` or
 * `LibraryExtension`).
 *
 * AGP compatibility: designed against 4.2.2 APIs (legacy Transform).
 * Still functional on 7.x — `android.registerTransform` is deprecated
 * there but operational. For 8.x a migration to
 * `AsmClassVisitorFactory` would be required; this plugin explicitly
 * targets the HMI's 4.2.2 environment (see NETSCOPE_AOP_REQUEST.md §10).
 *
 * Co-existence with AspectJ: the NetScope Transform visits
 * AspectJ-already-woven class bytes and explicitly skips any class
 * whose name contains `$ajc$` or ends with `$AjcClosure`. Host apps
 * should apply this plugin AFTER the AspectJ plugin so our Transform
 * runs last; see `docs/AOP_INTEGRATION.md`.
 */
class NetScopePlugin : Plugin<Project> {

    override fun apply(project: Project) {
        val log: Logger = project.logger
        val app = project.extensions.findByType(AppExtension::class.java)
        val lib = project.extensions.findByType(LibraryExtension::class.java)
        when {
            app != null -> {
                app.registerTransform(NetScopeTransform(log))
                log.lifecycle("[NetScope] registered Transform on application module ${project.path}")
            }
            lib != null -> {
                lib.registerTransform(NetScopeTransform(log))
                log.lifecycle("[NetScope] registered Transform on library module ${project.path}")
            }
            else -> {
                log.warn(
                    "[NetScope] plugin applied to ${project.path} but no Android " +
                    "extension (AppExtension/LibraryExtension) found. Apply the Android " +
                    "plugin BEFORE `indi.arrowyi.netscope`."
                )
            }
        }
    }
}
