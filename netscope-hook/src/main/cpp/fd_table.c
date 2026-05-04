#include "fd_table.h"

#include <string.h>
#include <stdlib.h>
#include <pthread.h>
/* ── Live fd tracking ───────────────────────────────────────────────────── */

#define MAX_FD 4096
#define LOCK_STRIPES 64

typedef struct {
    char     remote_addr[64];
    int64_t  tx_bytes;   /* protected by g_fd_locks[fd % LOCK_STRIPES] */
    int64_t  rx_bytes;
    int      active;     /* 1 = tracking this fd, 0 = empty slot */
} FdRecord;

static FdRecord           g_fd[MAX_FD];
static pthread_mutex_t    g_fd_locks[LOCK_STRIPES];

static inline pthread_mutex_t* fd_lock(int fd) {
    return &g_fd_locks[(unsigned)fd % LOCK_STRIPES];
}

/* ── Aggregation table ──────────────────────────────────────────────────── */

#define AGG_SLOTS 512

typedef struct {
    char    addr[64];
    int64_t tx;
    int64_t rx;
    int     conn_count;
    int     used;
} AggSlot;

static AggSlot         g_agg[AGG_SLOTS];
static pthread_mutex_t g_agg_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t str_hash(const char* s) {
    uint32_t h = 2166136261u;
    while (*s) { h = (h ^ (uint8_t)*s++) * 16777619u; }
    return h;
}

/* Find or create a slot for addr. Must be called with g_agg_lock held.
 * Returns slot index or -1 if table is full. */
static int agg_find_slot(const char* addr) {
    uint32_t idx = str_hash(addr) & (AGG_SLOTS - 1);
    for (int i = 0; i < AGG_SLOTS; i++) {
        AggSlot* s = &g_agg[(idx + i) & (AGG_SLOTS - 1)];
        if (!s->used) {
            strncpy(s->addr, addr, sizeof(s->addr) - 1);
            s->addr[sizeof(s->addr) - 1] = '\0';
            s->used = 1;
            return (idx + i) & (AGG_SLOTS - 1);
        }
        if (strncmp(s->addr, addr, sizeof(s->addr)) == 0) {
            return (idx + i) & (AGG_SLOTS - 1);
        }
    }
    return -1; /* table full — drop silently */
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void fd_table_init(void) {
    memset(g_fd, 0, sizeof(g_fd));
    memset(g_agg, 0, sizeof(g_agg));
    for (int i = 0; i < LOCK_STRIPES; i++) {
        pthread_mutex_init(&g_fd_locks[i], NULL);
    }
}

void fd_table_connect(int fd, const char* remote_addr) {
    if (fd < 0 || fd >= MAX_FD || !remote_addr) return;
    pthread_mutex_lock(fd_lock(fd));
    g_fd[fd].active = 1;
    g_fd[fd].tx_bytes = 0;
    g_fd[fd].rx_bytes = 0;
    strncpy(g_fd[fd].remote_addr, remote_addr, sizeof(g_fd[fd].remote_addr) - 1);
    g_fd[fd].remote_addr[sizeof(g_fd[fd].remote_addr) - 1] = '\0';
    pthread_mutex_unlock(fd_lock(fd));
}

void fd_table_add_tx(int fd, int64_t bytes) {
    if (fd < 0 || fd >= MAX_FD || bytes <= 0) return;
    pthread_mutex_lock(fd_lock(fd));
    if (g_fd[fd].active) g_fd[fd].tx_bytes += bytes;
    pthread_mutex_unlock(fd_lock(fd));
}

void fd_table_add_rx(int fd, int64_t bytes) {
    if (fd < 0 || fd >= MAX_FD || bytes <= 0) return;
    pthread_mutex_lock(fd_lock(fd));
    if (g_fd[fd].active) g_fd[fd].rx_bytes += bytes;
    pthread_mutex_unlock(fd_lock(fd));
}

void fd_table_close(int fd) {
    if (fd < 0 || fd >= MAX_FD) return;

    pthread_mutex_lock(fd_lock(fd));
    if (!g_fd[fd].active) {
        pthread_mutex_unlock(fd_lock(fd));
        return;
    }
    char   addr[64];
    int64_t tx = g_fd[fd].tx_bytes;
    int64_t rx = g_fd[fd].rx_bytes;
    strncpy(addr, g_fd[fd].remote_addr, sizeof(addr));
    g_fd[fd].active = 0;
    pthread_mutex_unlock(fd_lock(fd));

    /* Accumulate into aggregation table */
    pthread_mutex_lock(&g_agg_lock);
    int slot = agg_find_slot(addr);
    if (slot >= 0) {
        g_agg[slot].tx += tx;
        g_agg[slot].rx += rx;
        g_agg[slot].conn_count++;
    }
    pthread_mutex_unlock(&g_agg_lock);
}

int fd_table_snapshot(AggEntry* out, int max_entries) {
    if (!out || max_entries <= 0) return 0;
    int count = 0;
    pthread_mutex_lock(&g_agg_lock);
    for (int i = 0; i < AGG_SLOTS && count < max_entries; i++) {
        if (!g_agg[i].used) continue;
        strncpy(out[count].remote_addr, g_agg[i].addr, sizeof(out[count].remote_addr) - 1);
        out[count].remote_addr[sizeof(out[count].remote_addr) - 1] = '\0';
        out[count].tx_bytes   = g_agg[i].tx;
        out[count].rx_bytes   = g_agg[i].rx;
        out[count].conn_count = g_agg[i].conn_count;
        count++;
    }
    pthread_mutex_unlock(&g_agg_lock);
    return count;
}

void fd_table_total(int64_t* out_tx, int64_t* out_rx, int* out_conn) {
    int64_t tx = 0, rx = 0; int cn = 0;
    pthread_mutex_lock(&g_agg_lock);
    for (int i = 0; i < AGG_SLOTS; i++) {
        if (!g_agg[i].used) continue;
        tx += g_agg[i].tx;
        rx += g_agg[i].rx;
        cn += g_agg[i].conn_count;
    }
    pthread_mutex_unlock(&g_agg_lock);
    if (out_tx) *out_tx = tx;
    if (out_rx) *out_rx = rx;
    if (out_conn) *out_conn = cn;
}

void fd_table_clear(void) {
    pthread_mutex_lock(&g_agg_lock);
    memset(g_agg, 0, sizeof(g_agg));
    pthread_mutex_unlock(&g_agg_lock);
}
