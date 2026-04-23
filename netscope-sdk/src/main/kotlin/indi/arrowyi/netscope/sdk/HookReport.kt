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
     * A critical failure occurred (e.g. SIGSEGV during xhook_refresh, or
     * libc symbol resolution failed). No traffic data will be collected
     * for this process. Prompt the user / log to crashlytics.
     */
    FAILED(3);

    companion object {
        @JvmStatic
        fun fromNative(value: Int): Status =
            values().firstOrNull { it.nativeValue == value } ?: NOT_INITIALIZED
    }
}

/**
 * Detailed snapshot of which hooks succeeded. Constructed by the native
 * layer — DO NOT change the constructor signature without also updating
 * `build_hook_report()` in netscope_jni.cpp.
 *
 * @param statusCode     raw enum value; use [status] for the typed form
 * @param libcResolved   `true` iff all critical libc functions were resolved via dlsym
 * @param connectOk      `true` iff connect() hook registered without error
 * @param dnsOk          `true` iff getaddrinfo() hook registered without error
 * @param sendRecvOk     `true` iff all send/recv/write/read hooks registered
 * @param closeOk        `true` iff close() hook registered without error
 * @param failureReason  empty when [status] is ACTIVE; otherwise a short
 *                       machine-readable reason suitable for logging
 */
data class HookReport(
    val statusCode: Int,
    val libcResolved: Boolean,
    val connectOk: Boolean,
    val dnsOk: Boolean,
    val sendRecvOk: Boolean,
    val closeOk: Boolean,
    val failureReason: String?
) {
    val status: Status get() = Status.fromNative(statusCode)

    /** Will traffic data be collected at all? False only when FAILED or NOT_INITIALIZED. */
    val isCollecting: Boolean get() = status == Status.ACTIVE || status == Status.DEGRADED
}
