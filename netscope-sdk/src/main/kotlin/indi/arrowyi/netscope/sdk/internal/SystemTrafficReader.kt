package indi.arrowyi.netscope.sdk.internal

/**
 * Thin seam over [android.net.TrafficStats] so the v2.0.2 Layer-A total
 * can be unit-tested on the JVM.
 *
 * Production path uses [DEFAULT], which reads the caller's own UID via
 * [android.os.Process.myUid] and returns kernel-level per-UID byte
 * counts from `xt_qtaguid` (pre-Q) / `eBPF` (Q+).
 *
 * Returns either a real long or the sentinel
 * [android.net.TrafficStats.UNSUPPORTED] (= -1) on exotic kernels
 * without the counter infrastructure. The caller is responsible for
 * handling the sentinel.
 */
internal interface SystemTrafficReader {

    /** Kernel-reported total tx bytes for our UID since device boot. */
    fun getUidTxBytes(): Long

    /** Kernel-reported total rx bytes for our UID since device boot. */
    fun getUidRxBytes(): Long

    companion object {
        /** Production reader. Captures own UID once at class-load. */
        val DEFAULT: SystemTrafficReader = object : SystemTrafficReader {
            private val uid: Int = android.os.Process.myUid()
            override fun getUidTxBytes(): Long =
                android.net.TrafficStats.getUidTxBytes(uid)
            override fun getUidRxBytes(): Long =
                android.net.TrafficStats.getUidRxBytes(uid)
        }

        /** @return true if [value] signals "unsupported by this kernel". */
        const val UNSUPPORTED: Long = -1L
    }
}
