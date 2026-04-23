cmake_minimum_required(VERSION 3.22.1)
project("netscope")

# Hook backend: bytehook 1.1.1 (com.bytedance:bytehook, distributed as a
# Prefab package via the Android Gradle dependency).
#
# W^X safety requires TWO rules, both enforced in this codebase:
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
    core/dns_cache.cpp
    core/flow_table.cpp
    core/stats_aggregator.cpp
    utils/tls_sni_parser.cpp
    utils/ip_utils.cpp
)

target_include_directories(netscope PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(netscope
    bytehook::bytehook
    log
    android
)
