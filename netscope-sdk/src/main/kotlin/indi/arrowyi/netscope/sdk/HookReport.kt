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
     * - SIGSEGV during xhook_refresh, or
     * - libc symbol resolution failed, or
     * - **the post-install audit detected that GOT writes landed in
     *   non-executable memory** (typical on HONOR Android 10 with
     *   `extractNativeLibs=false`, where xhook 1.2.0 mis-parses the
     *   APK-embedded .so layout and writes stub pointers into random
     *   heap pages — see [HookReport.auditSlotsCorrupt] and
     *   [HookReport.auditHeapStubHits]).
     *
     * No traffic data will be collected for this process. Prompt the
     * user / log to crashlytics.
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
 *                            **nonzero means xhook misrouted a write** and forces FAILED
 * @param auditHeapStubHits   how many stub addresses were found floating in rw-p anonymous
 *                            heap memory (smoking-gun for the xhook+APK-embedded bug);
 *                            **nonzero forces FAILED**
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
    val failureReason: String?
) {
    val status: Status get() = Status.fromNative(statusCode)

    /** Will traffic data be collected at all? False only when FAILED or NOT_INITIALIZED. */
    val isCollecting: Boolean get() = status == Status.ACTIVE || status == Status.DEGRADED

    /**
     * True iff the post-install audit found at least one GOT slot that
     * xhook wrote into non-executable memory, or at least one stub
     * address lurking in the heap. These are the indicators for the
     * HONOR Android 10 / xhook 1.2.0 / extractNativeLibs=false crash
     * scenario. When true the SDK has already self-disabled.
     */
    val auditFoundCorruption: Boolean get() = auditSlotsCorrupt > 0 || auditHeapStubHits > 0
}
