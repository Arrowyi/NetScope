#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Install PLT hooks for network syscall wrappers.
 * Returns number of GOT entries patched (>0 = success). */
int socket_proxy_install(void);

/* Restore all GOT entries to their original values. */
void socket_proxy_uninstall(void);

#ifdef __cplusplus
}
#endif
