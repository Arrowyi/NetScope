package indi.arrowyi.netscope.hook

/**
 * Aggregate totals from the socket-level hook (Layer D).
 *
 * Compare against [indi.arrowyi.netscope.sdk.NetScope.getTotalStats] (Layer A)
 * to check coverage: if [txTotal] ≈ Layer A txTotal, the hook is capturing
 * all outbound traffic.
 *
 * @property txTotal        cumulative bytes sent across all tracked sockets.
 * @property rxTotal        cumulative bytes received across all tracked sockets.
 * @property connectionCount total number of completed TCP connections.
 */
data class SocketTotalStats(
    val txTotal: Long,
    val rxTotal: Long,
    val connectionCount: Int
) {
    val totalBytes: Long get() = txTotal + rxTotal
}
