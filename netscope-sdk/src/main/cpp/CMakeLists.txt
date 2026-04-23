cmake_minimum_required(VERSION 3.22.1)
project("netscope")

# Hook backend: bytehook 1.1.1 (com.bytedance:bytehook, distributed as a
# Prefab package via the Android Gradle dependency). We reference the
# prefab package for HEADERS ONLY and soft-load libbytehook.so at runtime
# via dlopen + dlsym from hook/bytehook_runtime.cpp.
#
# Why NOT link against bytehook::bytehook:
#   That would put libbytehook.so into libnetscope.so's DT_NEEDED, so the
#   Android loader would map it (and its own DT_NEEDED libshadowhook.so)
#   the instant `System.loadLibrary("netscope")` runs — firing every
#   __attribute__((constructor)) in the bytehook/shadowhook chain before
#   we ever see a single NetScope API call. HMI's 2026-04-23 triage on
#   HONOR AGM3-W09HN / EMUI 11 proved THIS specific path is what crashes
#   asdk.httpclient ~14 s later: the tombstone reproduced verbatim with
#   DEBUG_ULTRA_MINIMAL (NetScope runtime does nothing beyond dlsym on
#   libc) — evidence that the trigger is inside bytehook/shadowhook's
#   static-init, not inside any code we actively execute. By removing
#   libbytehook.so from DT_NEEDED and only dlopen-ing it on demand, we
#   gain a clean kill switch: DEBUG_ULTRA_MINIMAL means libbytehook.so
#   never appears in /proc/self/maps.
#
# W^X safety still requires TWO rules, both enforced in this codebase:
#   1. Init bytehook in BYTEHOOK_MODE_MANUAL (hook_manager.cpp).
#   2. Never use BYTEHOOK_CALL_PREV in proxies — call the real libc
#      via libc().fn() (hook_*.cpp + libc_funcs.{h,cpp}).
# Under these two rules the AUTOMATIC-only path bh_trampo_alloc →
# mmap(PROT_EXEC) is structurally unreachable; see docs/HOOK_EVOLUTION.md §P1.
#
# History & full migration rationale: docs/HOOK_EVOLUTION.md
find_package(bytehook REQUIRED CONFIG)

add_library(netscope SHARED
    netscope_jni.cpp
    hook/hook_manager.cpp
    hook/hook_connect.cpp
    hook/hook_dns.cpp
    hook/hook_send_recv.cpp
    hook/hook_close.cpp
    hook/libc_funcs.cpp
    hook/got_audit.cpp
    hook/hook_stubs.cpp
    hook/bytehook_runtime.cpp
    core/dns_cache.cpp
    core/flow_table.cpp
    core/stats_aggregator.cpp
    utils/tls_sni_parser.cpp
    utils/ip_utils.cpp
)

target_include_directories(netscope PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# Pull in bytehook HEADERS ONLY — never link, to keep libbytehook.so out
# of DT_NEEDED. See block comment at top of file.
get_target_property(_BYTEHOOK_INC bytehook::bytehook INTERFACE_INCLUDE_DIRECTORIES)
if(_BYTEHOOK_INC)
    target_include_directories(netscope PRIVATE ${_BYTEHOOK_INC})
else()
    message(FATAL_ERROR "bytehook::bytehook target found but INTERFACE_INCLUDE_DIRECTORIES is empty")
endif()

target_link_libraries(netscope
    log
    android
    dl
)
