package indi.arrowyi.sdk

/**
 * Traffic statistics for a single domain.
 *
 * @param txBytesTotal   Cumulative bytes sent since [NetScope.init] or last [NetScope.clearStats]
 * @param rxBytesTotal   Cumulative bytes received
 * @param txBytesInterval Bytes sent in the current/last interval window
 * @param rxBytesInterval Bytes received in the current/last interval window
 * @param connCountTotal  Cumulative number of closed connections to this domain
 * @param connCountInterval Closed connections in the current/last interval window
 * @param lastActiveMs   System.currentTimeMillis() of last activity
 */
data class DomainStats(
    val domain: String,
    val txBytesTotal: Long,
    val rxBytesTotal: Long,
    val txBytesInterval: Long,
    val rxBytesInterval: Long,
    val connCountTotal: Int,
    val connCountInterval: Int,
    val lastActiveMs: Long
) {
    val totalBytes: Long get() = txBytesTotal + rxBytesTotal
}
