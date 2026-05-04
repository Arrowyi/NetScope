#include "got_patcher.h"

#include <elf.h>
#include <link.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <android/log.h>
#include <pthread.h>

#define TAG  "NetScope_GOT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

/* ── Saved patches (for uninstall) ─────────────────────────────────────── */

#define MAX_PATCHES 2048

typedef struct {
    void** got_entry;
    void*  orig_value;
} Patch;

static Patch           g_patches[MAX_PATCHES];
static int             g_patch_count = 0;
static pthread_mutex_t g_patch_lock = PTHREAD_MUTEX_INITIALIZER;

/* ── GOT write helper ───────────────────────────────────────────────────── */

static int page_size_v = 0;

static int get_page_size(void) {
    if (!page_size_v) page_size_v = (int)sysconf(_SC_PAGESIZE);
    return page_size_v;
}

static void* page_start(void* addr) {
    int ps = get_page_size();
    return (void*)((uintptr_t)addr & ~(uintptr_t)(ps - 1));
}

/* Write one GOT entry. Returns 0 on success, -1 on mprotect failure. */
static int write_got(void** entry, void* new_fn) {
    void* page = page_start(entry);
    int   ps   = get_page_size();
    /* Temporarily add PROT_WRITE to the already-mapped GOT page.
     * This is mprotect on an existing mapping — safe on W^X kernels
     * (differs from mmap(MAP_ANONYMOUS,PROT_EXEC) which is denied). */
    if (mprotect(page, ps, PROT_READ | PROT_WRITE) != 0) {
        LOGE("mprotect RW %p failed", entry);
        return -1;
    }
    void* prev = *entry;
    *entry = new_fn;
    /* Flush I-cache on ARM (no-op on x86). */
    __builtin___clear_cache((char*)entry, (char*)entry + sizeof(void*));
    /* Restore read-only (failure here is non-fatal — leave it writable). */
    mprotect(page, ps, PROT_READ);
    (void)prev;
    return 0;
}

/* ── dl_iterate_phdr callback ───────────────────────────────────────────── */

typedef struct {
    HookDesc* hooks;
    int       hook_count;
    int       patched;   /* running total across all .so files */
} WalkData;

static int walk_cb(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    WalkData* wd = (WalkData*)data;

    ElfW(Addr) load_bias = info->dlpi_addr;

    /* Find PT_DYNAMIC. */
    const ElfW(Phdr)* dyn_phdr = NULL;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn_phdr = &info->dlpi_phdr[i];
            break;
        }
    }
    if (!dyn_phdr) return 0;

    const ElfW(Dyn)* dyn  = (const ElfW(Dyn)*)(load_bias + dyn_phdr->p_vaddr);

    uintptr_t    plt_rel   = 0;
    size_t       plt_sz    = 0;
    const char*  strtab    = NULL;
    const ElfW(Sym)* symtab = NULL;
    int          is_rela   = 0;

    for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_JMPREL:   plt_rel = load_bias + d->d_un.d_ptr; break;
            case DT_PLTRELSZ: plt_sz  = d->d_un.d_val;             break;
            case DT_STRTAB:   strtab  = (const char*)(load_bias + d->d_un.d_ptr); break;
            case DT_SYMTAB:   symtab  = (const ElfW(Sym)*)(load_bias + d->d_un.d_ptr); break;
            case DT_PLTREL:   is_rela = (d->d_un.d_val == DT_RELA); break;
        }
    }
    if (!plt_rel || !plt_sz || !strtab || !symtab) return 0;

    /* Iterate PLT relocations and patch matching symbols. */
    if (is_rela) {
        const ElfW(Rela)* rela = (const ElfW(Rela)*)plt_rel;
        size_t n = plt_sz / sizeof(ElfW(Rela));
        for (size_t i = 0; i < n; i++) {
            size_t      sym_idx  = ELF64_R_SYM(rela[i].r_info);
            const char* sym_name = strtab + symtab[sym_idx].st_name;
            void**      got      = (void**)(load_bias + rela[i].r_offset);
            for (int j = 0; j < wd->hook_count; j++) {
                if (strcmp(sym_name, wd->hooks[j].symbol) != 0) continue;
                /* Check we haven't already patched this exact GOT slot
                 * (two .so files sharing a PLT entry is impossible, but
                 * dl_iterate_phdr may visit overlapping segments). */
                int already = 0;
                for (int k = 0; k < g_patch_count; k++) {
                    if (g_patches[k].got_entry == got) { already = 1; break; }
                }
                if (already) continue;
                void* prev = *got;
                if (write_got(got, wd->hooks[j].stub) == 0) {
                    if (g_patch_count < MAX_PATCHES) {
                        g_patches[g_patch_count].got_entry  = got;
                        g_patches[g_patch_count].orig_value = prev;
                        g_patch_count++;
                    }
                    wd->patched++;
                }
            }
        }
    } else {
        /* REL (ARM32) */
        const ElfW(Rel)* rel = (const ElfW(Rel)*)plt_rel;
        size_t n = plt_sz / sizeof(ElfW(Rel));
        for (size_t i = 0; i < n; i++) {
            size_t      sym_idx  = ELF32_R_SYM(rel[i].r_info);
            const char* sym_name = strtab + symtab[sym_idx].st_name;
            void**      got      = (void**)(load_bias + rel[i].r_offset);
            for (int j = 0; j < wd->hook_count; j++) {
                if (strcmp(sym_name, wd->hooks[j].symbol) != 0) continue;
                int already = 0;
                for (int k = 0; k < g_patch_count; k++) {
                    if (g_patches[k].got_entry == got) { already = 1; break; }
                }
                if (already) continue;
                void* prev = *got;
                if (write_got(got, wd->hooks[j].stub) == 0) {
                    if (g_patch_count < MAX_PATCHES) {
                        g_patches[g_patch_count].got_entry  = got;
                        g_patches[g_patch_count].orig_value = prev;
                        g_patch_count++;
                    }
                    wd->patched++;
                }
            }
        }
    }
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int got_patcher_install(HookDesc* hooks, int count) {
    if (!hooks || count <= 0) return 0;

    /* Resolve original function pointers via dlsym(RTLD_NEXT). */
    for (int i = 0; i < count; i++) {
        *hooks[i].orig = dlsym(RTLD_NEXT, hooks[i].symbol);
        if (!*hooks[i].orig) {
            LOGE("dlsym(RTLD_NEXT, \"%s\") failed", hooks[i].symbol);
        }
    }

    pthread_mutex_lock(&g_patch_lock);
    g_patch_count = 0;
    WalkData wd = { hooks, count, 0 };
    dl_iterate_phdr(walk_cb, &wd);
    pthread_mutex_unlock(&g_patch_lock);

    LOGI("installed %d GOT patches for %d symbols", wd.patched, count);
    return wd.patched;
}

void got_patcher_uninstall(void) {
    pthread_mutex_lock(&g_patch_lock);
    for (int i = 0; i < g_patch_count; i++) {
        write_got(g_patches[i].got_entry, g_patches[i].orig_value);
    }
    int n = g_patch_count;
    g_patch_count = 0;
    pthread_mutex_unlock(&g_patch_lock);
    LOGI("removed %d GOT patches", n);
}
