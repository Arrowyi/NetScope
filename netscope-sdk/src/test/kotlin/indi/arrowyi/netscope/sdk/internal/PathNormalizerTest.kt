package indi.arrowyi.netscope.sdk.internal

import org.junit.Assert.assertEquals
import org.junit.Test

class PathNormalizerTest {

    @Test fun `null and empty collapse to slash`() {
        assertEquals("/", PathNormalizer.normalize(null))
        assertEquals("/", PathNormalizer.normalize(""))
        assertEquals("/", PathNormalizer.normalize("/"))
    }

    @Test fun `strips query string`() {
        assertEquals("/search", PathNormalizer.normalize("/search?q=hello&page=2"))
    }

    @Test fun `strips fragment`() {
        assertEquals("/users", PathNormalizer.normalize("/users#anchor"))
    }

    @Test fun `numeric segments become colon id`() {
        assertEquals("/users/:id", PathNormalizer.normalize("/users/123"))
        assertEquals("/users/:id/posts/:id", PathNormalizer.normalize("/users/123/posts/456"))
        assertEquals("/v1/:id/:id/:id", PathNormalizer.normalize("/v1/1/22/333"))
    }

    @Test fun `uuid segments become colon uuid`() {
        val uuid = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
        assertEquals("/accounts/:uuid/avatar",
            PathNormalizer.normalize("/accounts/$uuid/avatar"))
        // Case-insensitive
        assertEquals("/x/:uuid",
            PathNormalizer.normalize("/x/A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D"))
    }

    @Test fun `long hex with letters becomes colon hash`() {
        assertEquals("/file/:hash",
            PathNormalizer.normalize("/file/0af7e4c2e1f8bb93"))
        assertEquals("/blob/:hash",
            PathNormalizer.normalize("/blob/DEADBEEFCAFEBABE0123456789abcdef"))
    }

    @Test fun `pure numeric long strings take the id arm not the hash arm`() {
        // 20-digit all-numeric — NUMERIC arm wins over HEX arm.
        assertEquals("/x/:id", PathNormalizer.normalize("/x/12345678901234567890"))
    }

    @Test fun `short hex strings stay literal`() {
        // 8 hex chars — not long enough for :hash, not pure digits
        assertEquals("/etag/deadbeef", PathNormalizer.normalize("/etag/deadbeef"))
    }

    @Test fun `natural-language slugs are preserved`() {
        assertEquals("/articles/how-to-build-netscope",
            PathNormalizer.normalize("/articles/how-to-build-netscope"))
    }

    @Test fun `mixed real-world paths`() {
        assertEquals(
            "/api/v2/users/:id/posts/:id/comments",
            PathNormalizer.normalize("/api/v2/users/42/posts/7/comments")
        )
        assertEquals(
            "/api/v2/search",
            PathNormalizer.normalize("/api/v2/search?q=restaurants&lat=37.7&lng=-122.4")
        )
    }

    @Test fun `missing leading slash is added`() {
        assertEquals("/foo/:id", PathNormalizer.normalize("foo/123"))
    }

    @Test fun `consecutive slashes collapse cleanly`() {
        // `//` in input becomes an empty segment — we skip it so the
        // output doesn't contain `//` either.
        assertEquals("/foo/bar", PathNormalizer.normalize("/foo//bar"))
    }

    @Test fun `trailing slash is stripped so x and x slash aggregate together`() {
        // HMIs want `/users/123` and `/users/123/` to roll up as one API.
        assertEquals("/users/:id", PathNormalizer.normalize("/users/123/"))
    }
}
