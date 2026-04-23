#include "got_audit.h"
#include "libc_funcs.h"
#include "../netscope_log.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <unistd.h>

namespace netscope {

// ─── Target symbols ─────────────────────────────────────────────────────────

static const char* const kHooked[] = {
    "connect", "close", "getaddrinfo",
    "send", "sendto", "write", "writev",
    "recv", "recvfrom", "read", "readv",
};
static constexpr size_t kHookedCount = sizeof(kHooked) / sizeof(kHooked[0]);

static bool is_hooked_symbol(const char* name) {
    if (!name) return false;
    for (size_t i = 0; i < kHookedCount; ++i) {
        if (std::strcmp(name, kHooked[i]) == 0) return true;
    }
    return false;
}

// ─── libnetscope.so .text range ─────────────────────────────────────────────

namespace {
struct TextRange { uintptr_t start = 0; uintptr_t end = 0; bool ready = false; };
}
static TextRange g_netscope_text;

static int find_netscope_cb(struct dl_phdr_info* info, size_t, void* data) {
    if (!info->dlpi_name) return 0;
    if (!std::strstr(info->dlpi_name, "libnetscope.so")) return 0;
    auto* tr = static_cast<TextRange*>(data);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        if (!(ph.p_flags & PF_X)) continue;
        uintptr_t s = (uintptr_t)info->dlpi_addr + (uintptr_t)ph.p_vaddr;
        uintptr_t e = s + (uintptr_t)ph.p_memsz;
        if (tr->start == 0 || s < tr->start) tr->start = s;
        if (e > tr->end) tr->end = e;
    }
    return 1; // stop iteration
}

static void ensure_netscope_text() {
    if (g_netscope_text.ready) return;
    dl_iterate_phdr(find_netscope_cb, &g_netscope_text);
    g_netscope_text.ready = true;
    if (g_netscope_text.end > g_netscope_text.start) {
        LOGI("got_audit: libnetscope.so .text=[%p, %p) size=%zuKB",
             (void*)g_netscope_text.start, (void*)g_netscope_text.end,
             (size_t)((g_netscope_text.end - g_netscope_text.start) / 1024));
    } else {
        LOGW("got_audit: libnetscope.so .text range not found — audit will be partial");
    }
}

static bool is_our_stub(uintptr_t v) {
    return g_netscope_text.end > g_netscope_text.start
        && v >= g_netscope_text.start && v < g_netscope_text.end;
}

// ─── real libc match ────────────────────────────────────────────────────────

static bool is_real_libc(const char* sym, uintptr_t v) {
    const LibcFuncs& l = libc();
#define M(name) if (std::strcmp(sym, #name) == 0) return reinterpret_cast<uintptr_t>(l.name) == v
    M(connect); M(close); M(getaddrinfo);
    M(send); M(sendto); M(write); M(writev);
    M(recv); M(recvfrom); M(read); M(readv);
#undef M
    return false;
}

// ─── /proc/self/maps ────────────────────────────────────────────────────────

namespace {
struct MapRegion {
    uintptr_t   start;
    uintptr_t   end;
    char        perms[5]; // "rwxp\0"
    std::string path;
};
}

static bool parse_maps(std::vector<MapRegion>* out) {
    FILE* fp = std::fopen("/proc/self/maps", "re");
    if (!fp) return false;
    char line[2048];
    while (std::fgets(line, sizeof(line), fp)) {
        MapRegion r{};
        unsigned long long s = 0, e = 0;
        char perms[5] = {};
        int path_off = 0;
        // start-end perms offset dev inode path
        if (std::sscanf(line, "%llx-%llx %4s %*s %*s %*s %n",
                        &s, &e, perms, &path_off) < 3) continue;
        r.start = (uintptr_t)s;
        r.end   = (uintptr_t)e;
        std::memcpy(r.perms, perms, 4);
        r.perms[4] = '\0';
        if (path_off > 0) {
            const char* p = line + path_off;
            // trim leading spaces + trailing newline
            while (*p == ' ' || *p == '\t') ++p;
            r.path = p;
            while (!r.path.empty() && (r.path.back() == '\n' || r.path.back() == '\r'
                                       || r.path.back() == ' '))
                r.path.pop_back();
        }
        out->push_back(std::move(r));
    }
    std::fclose(fp);
    return true;
}

static const MapRegion* find_region(const std::vector<MapRegion>& maps, uintptr_t addr) {
    for (const auto& r : maps) if (addr >= r.start && addr < r.end) return &r;
    return nullptr;
}

static bool is_executable(const MapRegion* r) { return r && r->perms[2] == 'x'; }

static bool is_rw_anon_heap(const MapRegion& r) {
    if (r.perms[0] != 'r' || r.perms[1] != 'w') return false;
    if (r.perms[2] == 'x') return false;
    if (r.path.empty()) return true;
    if (r.path.find("[anon:libc_malloc") != std::string::npos) return true;
    if (r.path.find("[anon:scudo")      != std::string::npos) return true;
    if (r.path == "[heap]") return true;
    return false;
}

// ─── PT_DYNAMIC walk ────────────────────────────────────────────────────────

namespace {
struct DynTabs {
    const ElfW(Sym)* symtab      = nullptr;
    const char*      strtab      = nullptr;
    size_t           strtab_size = 0;
    const void*      jmprel      = nullptr;
    size_t           jmprel_size = 0;
};
}

// Android linker is inconsistent about whether DT_{SYMTAB,STRTAB,JMPREL}
// values are stored as absolute addresses or segment offsets. Be defensive:
// if the stored value is smaller than the load base, treat it as an offset
// and add dlpi_addr.
static inline uintptr_t resolve_ptr(const dl_phdr_info* info, uintptr_t raw) {
    if (raw == 0) return 0;
    if (raw < (uintptr_t)info->dlpi_addr) return raw + (uintptr_t)info->dlpi_addr;
    return raw;
}

static bool parse_dynamic(const dl_phdr_info* info, DynTabs* out) {
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_DYNAMIC) continue;
        auto* dyn = reinterpret_cast<const ElfW(Dyn)*>(
            (uintptr_t)info->dlpi_addr + (uintptr_t)ph.p_vaddr);
        for (; dyn->d_tag != DT_NULL; ++dyn) {
            switch (dyn->d_tag) {
                case DT_SYMTAB:
                    out->symtab = reinterpret_cast<const ElfW(Sym)*>(
                        resolve_ptr(info, (uintptr_t)dyn->d_un.d_ptr));
                    break;
                case DT_STRTAB:
                    out->strtab = reinterpret_cast<const char*>(
                        resolve_ptr(info, (uintptr_t)dyn->d_un.d_ptr));
                    break;
                case DT_STRSZ:
                    out->strtab_size = (size_t)dyn->d_un.d_val;
                    break;
                case DT_JMPREL:
                    out->jmprel = reinterpret_cast<const void*>(
                        resolve_ptr(info, (uintptr_t)dyn->d_un.d_ptr));
                    break;
                case DT_PLTRELSZ:
                    out->jmprel_size = (size_t)dyn->d_un.d_val;
                    break;
                default: break;
            }
        }
        return out->symtab && out->strtab && out->jmprel && out->jmprel_size;
    }
    return false;
}

// ─── Audit context ──────────────────────────────────────────────────────────

namespace {
struct AuditCtx {
    GotAuditResult                result;
    const std::vector<MapRegion>* maps;
    bool                          detail_set;
};
}

__attribute__((format(printf, 2, 3)))
static void note_detail(AuditCtx* ctx, const char* fmt, ...) {
    if (ctx->detail_set) return;
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(ctx->result.first_detail, sizeof(ctx->result.first_detail), fmt, ap);
    va_end(ap);
    ctx->detail_set = true;
}

// ─── Per-lib audit ──────────────────────────────────────────────────────────

static void audit_one_lib(AuditCtx* ctx, const dl_phdr_info* info) {
    const char* libname = (info->dlpi_name && *info->dlpi_name)
                        ? info->dlpi_name : "(unnamed)";
    ctx->result.libs_scanned++;
    if (std::strstr(libname, "libnetscope.so")) return;  // we don't hook ourselves

    DynTabs d{};
    if (!parse_dynamic(info, &d)) {
        ctx->result.libs_skipped++;
        return;
    }

#if defined(__LP64__)
    const auto* rel = reinterpret_cast<const Elf64_Rela*>(d.jmprel);
    const size_t n  = d.jmprel_size / sizeof(Elf64_Rela);
#else
    const auto* rel = reinterpret_cast<const Elf32_Rel*>(d.jmprel);
    const size_t n  = d.jmprel_size / sizeof(Elf32_Rel);
#endif

    for (size_t i = 0; i < n; ++i) {
#if defined(__LP64__)
        const Elf64_Rela& r   = rel[i];
        const uint32_t    typ = ELF64_R_TYPE(r.r_info);
        const uint32_t    idx = ELF64_R_SYM(r.r_info);
        if (typ != R_AARCH64_JUMP_SLOT) continue;
#else
        const Elf32_Rel&  r   = rel[i];
        const uint32_t    typ = ELF32_R_TYPE(r.r_info);
        const uint32_t    idx = ELF32_R_SYM(r.r_info);
        if (typ != R_ARM_JUMP_SLOT) continue;
#endif
        const ElfW(Sym)& sym = d.symtab[idx];
        uint32_t name_off = sym.st_name;
        if (d.strtab_size && name_off >= d.strtab_size) continue;
        const char* name = d.strtab + name_off;
        if (!is_hooked_symbol(name)) continue;

        uintptr_t got_va = (uintptr_t)info->dlpi_addr + (uintptr_t)r.r_offset;
        uintptr_t val    = *reinterpret_cast<uintptr_t*>(got_va);

        ctx->result.slots_total++;

        if (is_our_stub(val)) { ctx->result.slots_to_our_stub++; continue; }
        if (is_real_libc(name, val)) { ctx->result.slots_to_real_libc++; continue; }

        const MapRegion* reg = find_region(*ctx->maps, val);
        if (is_executable(reg)) {
            ctx->result.slots_to_other_text++;
            note_detail(ctx, "chained:%s@%s val=%p in %s",
                        name, libname, (void*)val,
                        reg->path.empty() ? "(anon-x)" : reg->path.c_str());
            continue;
        }

        ctx->result.slots_corrupt++;
        const char* where = reg ? reg->path.c_str() : "(unmapped)";
        LOGE("got_audit: CORRUPT %s@%s got_va=%p val=%p in '%s' [%c%c%c%c]",
             name, libname, (void*)got_va, (void*)val,
             *where ? where : "(anon)",
             reg ? reg->perms[0] : '?',
             reg ? reg->perms[1] : '?',
             reg ? reg->perms[2] : '?',
             reg ? reg->perms[3] : '?');
        note_detail(ctx, "corrupt:%s@%s val=%p in %s",
                    name, libname, (void*)val,
                    *where ? where : "(anon)");
    }
}

static int audit_cb(struct dl_phdr_info* info, size_t, void* data) {
    audit_one_lib(static_cast<AuditCtx*>(data), info);
    return 0;
}

// ─── Optional heap scan ─────────────────────────────────────────────────────
//
// For each rw-p anonymous region, look for bytes that equal one of our
// stub addresses. If we find any, xhook wrote into the heap and the host
// app is about to crash the moment that object is used as a function
// pointer / vtable.

static void scan_anon_for_stubs(AuditCtx* ctx) {
    constexpr size_t kMaxScanBytes = 256ULL * 1024 * 1024;
    constexpr int    kMaxHits      = 32;
    size_t budget = kMaxScanBytes;
    for (const auto& r : *ctx->maps) {
        if (budget == 0) break;
        if (!is_rw_anon_heap(r)) continue;
        size_t span = r.end - r.start;
        size_t take = span < budget ? span : budget;
        budget -= take;
        ctx->result.anon_regions_scanned++;
        ctx->result.anon_bytes_scanned += take;

        auto* p = reinterpret_cast<const uintptr_t*>(r.start);
        const size_t words = take / sizeof(uintptr_t);
        for (size_t i = 0; i < words; ++i) {
            const uintptr_t v = p[i];
            if (is_our_stub(v)) {
                ctx->result.anon_stub_hits++;
                uintptr_t at = r.start + i * sizeof(uintptr_t);
                LOGE("got_audit: stub %p found at %p in '%s' — xhook wrote into heap",
                     (void*)v, (void*)at,
                     r.path.empty() ? "(anon)" : r.path.c_str());
                note_detail(ctx, "stub-in-heap:%p at %p in %s",
                            (void*)v, (void*)at,
                            r.path.empty() ? "(anon)" : r.path.c_str());
                if (ctx->result.anon_stub_hits >= kMaxHits) return;
            }
        }
    }
}

// ─── Public entry point ─────────────────────────────────────────────────────

GotAuditResult audit_got(bool scan_anon_heap) {
    ensure_netscope_text();

    AuditCtx ctx{};
    std::vector<MapRegion> maps;
    if (!parse_maps(&maps)) {
        LOGE("got_audit: /proc/self/maps unreadable");
    }
    ctx.maps = &maps;

    dl_iterate_phdr(audit_cb, &ctx);

    if (scan_anon_heap) scan_anon_for_stubs(&ctx);

    LOGI("got_audit: libs=%d skipped=%d slots total=%d stub=%d libc=%d other-text=%d CORRUPT=%d "
         "heap-regions=%zu heap-scanned=%zuKB heap-stub-hits=%d",
         ctx.result.libs_scanned, ctx.result.libs_skipped,
         ctx.result.slots_total, ctx.result.slots_to_our_stub,
         ctx.result.slots_to_real_libc, ctx.result.slots_to_other_text,
         ctx.result.slots_corrupt,
         ctx.result.anon_regions_scanned,
         ctx.result.anon_bytes_scanned / 1024,
         ctx.result.anon_stub_hits);

    return ctx.result;
}

} // namespace netscope
