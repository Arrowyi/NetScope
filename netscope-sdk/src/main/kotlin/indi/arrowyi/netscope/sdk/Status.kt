package indi.arrowyi.netscope.sdk

/**
 * Overall state of the NetScope AOP pipeline.
 *
 * The SDK is now pure Kotlin (no native hooks), so there are only two
 * realistic states. `DEGRADED` / `FAILED` were retired along with the
 * hook backend — see `docs/BYTEHOOK_LESSONS.md`.
 */
enum class Status {
    /** [NetScope.init] has not been called yet. */
    NOT_INITIALIZED,

    /** [NetScope.init] has run; stats are being collected. */
    ACTIVE
}
