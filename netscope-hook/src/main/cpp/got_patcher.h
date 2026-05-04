#pragma once
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One hook descriptor: symbol name, stub function pointer, and output
 * slot for the original libc function pointer (resolved via dlsym). */
typedef struct {
    const char* symbol;   /* e.g. "connect" */
    void*       stub;     /* our proxy function */
    void**      orig;     /* OUT: filled with dlsym(RTLD_NEXT, symbol) */
} HookDesc;

/* Install PLT hooks for all descriptors in the array.
 * Walks all loaded .so files via dl_iterate_phdr and patches GOT entries.
 * Returns number of distinct GOT entries patched (0 on error). */
int got_patcher_install(HookDesc* hooks, int count);

/* Restore all previously patched GOT entries to their original values.
 * Safe to call even if got_patcher_install was never called. */
void got_patcher_uninstall(void);

#ifdef __cplusplus
}
#endif
