package indi.arrowyi.netscope.sdk

/**
 * Traffic statistics for one API endpoint reported by a C++ HTTP client
 * (Layer C — `tn::http::client` callback).
 *
 * Same (host, path) key conventions as [ApiStats]. Source data comes from
 * `tn::http::client::restricted::injectGlobalOption` callbacks in the HMI's
 * native build (see `docs/cpp-bridge/`), forwarded to the SDK via
 * [NetScope.reportCppFlow].
 *
 * This layer is independent of Layer B ([ApiStats]) — both may record the
 * same endpoint if the HMI has both Java OkHttp calls and C++ HTTP calls
 * going to the same server. That is expected; the two layers cross-validate
 * each other, they are not additive.
 *
 * @property host           formatted endpoint — same rules as [ApiStats.host].
 * @property path           normalised URL path — same rules as [ApiStats.path].
 * @property txBytes        cumulative bytes sent since last [NetScope.clearCppApiStats].
 * @property rxBytes        cumulative bytes received.
 * @property requestCount   number of completed HTTP requests to this endpoint.
 * @property totalTransferTimeMs cumulative transfer time across all requests (ms).
 */
data class CppApiStats(
    val host: String,
    val path: String,
    val txBytes: Long,
    val rxBytes: Long,
    val requestCount: Int,
    val totalTransferTimeMs: Double
) {
    val key: String get() = "$host$path"
    val totalBytes: Long get() = txBytes + rxBytes
    val avgTransferTimeMs: Double
        get() = if (requestCount > 0) totalTransferTimeMs / requestCount else 0.0
}
