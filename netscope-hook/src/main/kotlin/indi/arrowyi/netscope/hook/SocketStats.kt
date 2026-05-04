package indi.arrowyi.netscope.hook

/**
 * Traffic statistics for one remote endpoint observed at the socket level
 * (Layer D — PLT hook on libc connect/send/recv).
 *
 * The key is a remote address string in the form `"ip:port"` (e.g.
 * `"203.0.113.1:443"` or `"[::1]:8080"`). Unlike Layers B and C, there
 * is no URL/path here — TCP knows only IP and port. HMIs can reverse-DNS
 * the IP to identify the service if needed.
 *
 * @property remoteAddress  remote endpoint as "ip:port" or "[ipv6]:port".
 * @property txBytes        cumulative bytes sent to this address.
 * @property rxBytes        cumulative bytes received from this address.
 * @property connectionCount number of completed TCP connections (fd close count).
 */
data class SocketStats(
    val remoteAddress: String,
    val txBytes: Long,
    val rxBytes: Long,
    val connectionCount: Int
) {
    val totalBytes: Long get() = txBytes + rxBytes
}
