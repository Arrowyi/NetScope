package indi.arrowyi.netscope.sdk.internal

/**
 * Collapse a raw URL path into a templated, low-cardinality form suitable
 * for use as an aggregation key.
 *
 * Rules applied per path segment, in this precedence order:
 *   1. UUID canonical form (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) → `:uuid`
 *   2. All-digits (`\d+`) → `:id`
 *   3. Long hex-with-at-least-one-letter (≥16 chars of `0-9a-fA-F` with
 *      at least one `a-f`) → `:hash`
 *   4. Otherwise the segment is kept as-is.
 *
 * Query string (`?...`) and fragment (`#...`) are stripped before
 * segmentation — the caller should not depend on them showing up in the
 * key. Consecutive slashes are collapsed, trailing slashes are dropped,
 * and a missing leading `/` is added so every output starts with `/`
 * and — for any non-root path — has no trailing `/`. This means
 * `/users/123` and `/users/123/` aggregate as the same API, which is
 * what HMIs want.
 *
 * Examples:
 * ```
 * /users/123/posts/456              → /users/:id/posts/:id
 * /accounts/a1b2c3d4-.../avatar     → /accounts/:uuid/avatar
 * /file/0af7e4c2e1f8bb93            → /file/:hash
 * /search?q=hello                   → /search
 * ""                                → /
 * ```
 *
 * This is intentionally conservative: we do NOT template segments that
 * merely "look high-entropy" (e.g. base64 tokens), because we don't want
 * to rewrite natural-language segments like `some-article-slug`. If
 * consumers need finer templating in the future, we can introduce a
 * pluggable `PathNormalizer` interface on the public API; for v3.0.0 the
 * built-in heuristics are the only option.
 */
internal object PathNormalizer {

    private val UUID_REGEX = Regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    private val NUMERIC_REGEX = Regex("^\\d+$")
    private val HEX_REGEX = Regex("^[0-9a-fA-F]{16,}$")

    fun normalize(rawPath: String?): String {
        if (rawPath.isNullOrEmpty()) return "/"
        val noQuery = rawPath.substringBefore('?').substringBefore('#')
        if (noQuery.isEmpty() || noQuery == "/") return "/"

        val withLeadingSlash = if (noQuery.startsWith('/')) noQuery else "/$noQuery"
        // Split into non-empty segments. This collapses runs of `/` (so
        // `/foo//bar` → `/foo/bar`) and drops any trailing slash (so
        // `/x/` and `/x` aggregate as the same API) — both are
        // desirable behaviours for HMI-facing keys.
        val segments = withLeadingSlash.split('/').filter { it.isNotEmpty() }
        if (segments.isEmpty()) return "/"
        val sb = StringBuilder(withLeadingSlash.length + 8)
        for (raw in segments) {
            sb.append('/')
            sb.append(replaceSegment(raw))
        }
        return sb.toString()
    }

    private fun replaceSegment(segment: String): String {
        if (UUID_REGEX.matches(segment)) return ":uuid"
        if (NUMERIC_REGEX.matches(segment)) return ":id"
        // Hex: must have at least one letter, otherwise it's pure-numeric
        // and was caught above — or a short all-digit string that doesn't
        // meet the 16-char hex threshold either. Both are fine.
        if (HEX_REGEX.matches(segment) && segment.any { it in 'a'..'f' || it in 'A'..'F' }) {
            return ":hash"
        }
        return segment
    }
}
