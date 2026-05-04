#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize the fd table and aggregation table. Call once at startup. */
void fd_table_init(void);

/* Called from connect() proxy — record fd -> remote_addr mapping.
 * remote_addr should be "ip:port" or "[ipv6]:port". */
void fd_table_connect(int fd, const char* remote_addr);

/* Called from send/write proxies — add tx bytes for fd.
 * No-op if fd is not a tracked socket. */
void fd_table_add_tx(int fd, int64_t bytes);

/* Called from recv/read proxies — add rx bytes for fd. */
void fd_table_add_rx(int fd, int64_t bytes);

/* Called from close() proxy — finalize fd stats into the aggregation table
 * and remove the fd entry. No-op if fd is not tracked. */
void fd_table_close(int fd);

/* ── Snapshot API (called from JNI on the Java thread) ─────────────────── */

typedef struct {
    char   remote_addr[64];
    int64_t tx_bytes;
    int64_t rx_bytes;
    int     conn_count;
} AggEntry;

/* Copy aggregation snapshot into caller-provided buffer. Returns number of
 * entries written (up to max_entries). */
int fd_table_snapshot(AggEntry* out, int max_entries);

/* Total bytes across all aggregated entries. */
void fd_table_total(int64_t* out_tx, int64_t* out_rx, int* out_conn);

/* Clear all aggregated stats (does not affect live fd entries). */
void fd_table_clear(void);

#ifdef __cplusplus
}
#endif
