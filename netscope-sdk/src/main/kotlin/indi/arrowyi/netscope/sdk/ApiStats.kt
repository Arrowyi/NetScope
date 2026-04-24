package indi.arrowyi.netscope.sdk

/**
 * Traffic statistics for a single API endpoint — i.e. one `host` +
 * one `path` combination.
 *
 * v3.0.0 replaces the old `DomainStats` (which keyed on `host` only).
 * Each HTTP request / URL-connection / WebSocket call site is
 * attributed to the tuple `(host, path)`, letting HMIs distinguish
 * `/v1/users` from `/v1/orders` even when they share a host.
 *
 * Keying rules, implemented by the instrumentation layer:
 *   1. `host` is either a resolvable name (e.g. `api.example.com`) or
 *      a raw IP. If the scheme's non-default port was used, it is
 *      folded into `host` as `host:port`, e.g. `api.example.com:8080`
 *      or `192.168.1.5:9000`. If neither a host nor a port is
 *      recoverable, `host` becomes `<unknown>` (constant
 *      `indi.arrowyi.netscope.sdk.internal.EndpointFormatter.UNKNOWN_HOST`).
 *      If only port is known, it becomes `<unknown>:$port`.
 *   2. `path` is the URL's decoded path with high-cardinality segments
 *      templated — numeric IDs → `:id`, UUIDs → `:uuid`, long hex
 *      strings → `:hash`. Query and fragment are dropped. GET and
 *      POST against the same endpoint merge.
 *   3. [key] is the canonical string identifier
 *      `"$host$path"`, e.g. `api.example.com/v1/users/:id`.
 *
 * @property host            formatted host (optionally `:port`) — see above.
 * @property path            normalised URL path, always starts with `/`.
 * @property key             `"$host$path"` — stable identifier used internally.
 * @property txBytesTotal    cumulative bytes sent since [NetScope.init] or
 *                           last [NetScope.clearStats].
 * @property rxBytesTotal    cumulative bytes received.
 * @property txBytesInterval bytes sent in the current/last interval window.
 * @property rxBytesInterval bytes received in the current/last interval window.
 * @property connCountTotal  cumulative number of closed flows to this API.
 * @property connCountInterval closed flows in the current/last interval.
 * @property lastActiveMs    `System.currentTimeMillis()` of last activity.
 */
data class ApiStats(
    val host: String,
    val path: String,
    val txBytesTotal: Long,
    val rxBytesTotal: Long,
    val txBytesInterval: Long,
    val rxBytesInterval: Long,
    val connCountTotal: Int,
    val connCountInterval: Int,
    val lastActiveMs: Long
) {
    /** Canonical identifier `"$host$path"` — e.g. `api.example.com/v1/users/:id`. */
    val key: String get() = "$host$path"

    /** Sum of tx+rx since init — handy for sort-by-loud. */
    val totalBytes: Long get() = txBytesTotal + rxBytesTotal
}
