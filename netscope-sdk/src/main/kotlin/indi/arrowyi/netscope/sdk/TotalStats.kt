package indi.arrowyi.netscope.sdk

/**
 * Sum of traffic observed by NetScope across every domain since
 * [NetScope.init] / last [NetScope.clearStats].
 *
 * NetScope only sees traffic that passes through a build-time
 * instrumented Java code path (OkHttp, HttpsURLConnection, OkHttp
 * WebSocket). Traffic originating from native C/C++ HTTP clients
 * (e.g. Telenav's `asdk.httpclient`) is counted by that library's own
 * stats, NOT here.
 *
 * The integration contract is therefore:
 *
 * ```
 *   total_app_traffic = NetScope.getTotalStats()  +  <native-stack stats>
 * ```
 *
 * @param txTotal       cumulative bytes sent  across all domains
 * @param rxTotal       cumulative bytes received across all domains
 * @param connCountTotal cumulative number of CLOSED flows across all domains
 */
data class TotalStats(
    val txTotal: Long,
    val rxTotal: Long,
    val connCountTotal: Int
) {
    val totalBytes: Long get() = txTotal + rxTotal
}
