package indi.arrowyi.netscope.sdk

/**
 * Overall state of the NetScope traffic-collection pipeline.
 *
 * The host application (HMI, debug overlay, crashlytics breadcrumb, etc.)
 * can query [NetScope.getHookReport] or observe [NetScope.setStatusListener]
 * to decide whether to show the user "traffic monitoring active" /
 * "partial data only" / "monitoring disabled".
 */
enum class Status(val nativeValue: Int) {
    /** [NetScope.init] has not been called, or was rolled back. */
    NOT_INITIALIZED(0),

    /** All hooks are installed and working; statistics are complete. */
    ACTIVE(1),

    /**
     * Some hooks failed to install but the SDK is still collecting data.
     * Traffic attribution may miss a subset of connections (e.g. DNS
     * resolutions if getaddrinfo hook failed). Check [HookReport] fields
     * and [HookReport.failureReason] for specifics.
     */
    DEGRADED(2),

    /**
     * A critical failure occurred:
     * - `bytehook_init` returned a non-OK code (most commonly due to a
     *   locked-down W^X kernel refusing `mmap(PROT_EXEC)` — see
     *   `docs/HOOK_EVOLUTION.md §P1`), or
     * - SIGSEGV during hook install, or
     * - libc symbol resolution failed, or
     * - the post-install audit detected that a GOT slot was overwritten
     *   with a non-executable address (see [HookReport.auditSlotsCorrupt]).
     *
     * No traffic data will be collected for this process. Prompt the
     * user / log to crashlytics. [HookReport.failureReason] contains a
     * short, machine-readable explanation.
     */
    FAILED(3);

    companion object {
        @JvmStatic
        fun fromNative(value: Int): Status =
            values().firstOrNull { it.nativeValue == value } ?: NOT_INITIALIZED
    }
}

/**
 * Detailed snapshot of hook installation + post-install audit results.
 *
 * DO NOT reorder constructor parameters without also updating the JNI
 * signature in `netscope_jni.cpp::build_hook_report`.
 *
 * @param statusCode          raw enum value; use [status] for the typed form
 * @param libcResolved        `true` iff all critical libc functions resolved via dlsym
 * @param connectOk           `true` iff connect() hook registered without error
 * @param dnsOk               `true` iff getaddrinfo() hook registered without error
 * @param sendRecvOk          `true` iff all send/recv/write/read hooks registered
 * @param closeOk             `true` iff close() hook registered without error
 * @param auditSlotsTotal     GOT relocations matching our hooked symbols across all loaded .so
 * @param auditSlotsHooked    of those, how many currently point to a NetScope stub (good)
 * @param auditSlotsUnhooked  of those, how many still point at the real libc symbol (benign)
 * @param auditSlotsChained   of those, how many point into some OTHER library's code
 *                            (a third-party hooker got there first — not a crash risk)
 * @param auditSlotsCorrupt   of those, how many point into rw-p data / non-executable memory —
 *                            **nonzero means the hooker misrouted a write** and forces FAILED
 * @param auditHeapStubHits   advisory count of stub addresses observed in rw-p heap
 *                            pages; legitimate copies abound (the hooker's own registry,
 *                            bionic sigaction table, soinfo) and this field on its own
 *                            does **not** affect [status]. Use for offline triage only
 * @param apkEmbeddedLibsSkipped legacy field from the xhook era — bytehook handles
 *                            `base.apk!/lib/...` layouts correctly, so this is always
 *                            0 in current builds. Retained for backwards compatibility
 * @param failureReason       empty when [status] is ACTIVE; otherwise a short
 *                            machine-readable reason suitable for logging
 */
data class HookReport(
    val statusCode: Int,
    val libcResolved: Boolean,
    val connectOk: Boolean,
    val dnsOk: Boolean,
    val sendRecvOk: Boolean,
    val closeOk: Boolean,
    val auditSlotsTotal: Int,
    val auditSlotsHooked: Int,
    val auditSlotsUnhooked: Int,
    val auditSlotsChained: Int,
    val auditSlotsCorrupt: Int,
    val auditHeapStubHits: Int,
    val apkEmbeddedLibsSkipped: Int,
    val failureReason: String?
) {
    val status: Status get() = Status.fromNative(statusCode)

    /** Will traffic data be collected at all? False only when FAILED or NOT_INITIALIZED. */
    val isCollecting: Boolean get() = status == Status.ACTIVE || status == Status.DEGRADED

    /**
     * True iff the post-install audit found at least one GOT slot that the
     * hooker overwrote with a non-executable address. When true the SDK
     * has already self-disabled — see [failureReason] for the specific
     * library / symbol / address.
     */
    val auditFoundCorruption: Boolean get() = auditSlotsCorrupt > 0
}
