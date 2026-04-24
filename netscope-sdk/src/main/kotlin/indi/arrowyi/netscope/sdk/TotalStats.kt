package indi.arrowyi.netscope.sdk

/**
 * Kernel-level total traffic for the app's UID since [NetScope.init] /
 * last [NetScope.clearStats].
 *
 * **Data source (v2.0.2+):** `android.net.TrafficStats.getUid{Tx,Rx}Bytes`
 * minus a baseline snapshot captured at [NetScope.init]. Covers
 * everything the kernel attributes to our UID — Java, Kotlin, C++,
 * NDK, signed native blobs, raw sockets — whether or not NetScope's
 * ASM instrumentation saw it. This is the "Layer A" number.
 *
 * By contrast [DomainStats] (from [NetScope.getDomainStats]) is
 * "Layer B" — only what the AOP-instrumented Java paths saw. The
 * invariant `sum(DomainStats.totalBytes) <= TotalStats.totalBytes` is
 * intentional; the delta is non-instrumented (usually native)
 * traffic.
 *
 * @param txTotal        kernel-counted bytes sent since init
 * @param rxTotal        kernel-counted bytes received since init
 * @param connCountTotal AOP-observed Java-layer flow-close count.
 *                       Remains a Java-only figure because the kernel
 *                       has no "connection close" concept for native
 *                       sockets.
 */
data class TotalStats(
    val txTotal: Long,
    val rxTotal: Long,
    val connCountTotal: Int
) {
    val totalBytes: Long get() = txTotal + rxTotal
}
