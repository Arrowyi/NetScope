package indi.arrowyi.netscope.sdk.internal

/**
 * Canonicalise the "host" component of an [indi.arrowyi.netscope.sdk.ApiStats]
 * key.
 *
 * Output rules:
 *   - Non-empty host, default-scheme port (or port unknown): returns just
 *     `host` (e.g. `api.example.com`, `192.168.1.5`).
 *   - Non-empty host, explicit non-default port: returns `host:port`
 *     (e.g. `api.example.com:8080`, `192.168.1.5:9000`).
 *   - Empty / blank host but port known: returns `<unknown>:port`
 *     (preserves whatever locator info we have).
 *   - Neither known: returns `<unknown>`.
 *
 * Callers pass:
 *   - `host`           — the raw host string the integration layer extracted.
 *                        May be null/blank if the URL had no authority
 *                        (rare with HTTP but possible with e.g. `jar:`,
 *                        some proxy / raw-socket call sites). IPs are
 *                        treated verbatim — `192.168.1.5:9000` shows up
 *                        literally, which is what HMIs want for surfacing
 *                        mystery connections.
 *   - `port`           — the URL's port, or -1 if unspecified.
 *   - `defaultPortForScheme` — the scheme default (e.g. 80 for HTTP, 443
 *                        for HTTPS, 80 for WS, 443 for WSS). Pass -1 if
 *                        you don't know / don't care to elide.
 *
 * Ports equal to `defaultPortForScheme` are elided so a garden-variety
 * HTTPS call stays "api.example.com" and does not pollute the domain
 * list with `:443` everywhere.
 */
internal object EndpointFormatter {

    const val UNKNOWN_HOST = "<unknown>"

    fun format(host: String?, port: Int, defaultPortForScheme: Int): String {
        val cleanHost = host?.takeIf { it.isNotBlank() }
        val showPort = port > 0 && port != defaultPortForScheme
        return when {
            cleanHost != null && showPort -> "$cleanHost:$port"
            cleanHost != null              -> cleanHost
            showPort                      -> "$UNKNOWN_HOST:$port"
            else                          -> UNKNOWN_HOST
        }
    }
}
