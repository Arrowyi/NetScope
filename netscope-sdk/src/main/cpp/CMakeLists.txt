cmake_minimum_required(VERSION 3.22.1)
project("netscope")

# Hook backend: bytehook 1.1.1 (com.bytedance:bytehook, distributed as a
# Prefab package via the Android Gradle dependency). Bytehook is a pure
# PLT/GOT patcher; our proxies never call BYTEHOOK_CALL_PREV, so bytehook
# operates without installing a PROT_EXEC trampoline for the prev chain.
# This keeps NetScope W^X-compatible on locked-down ROMs.
#
# History & migration rationale: docs/HOOK_EVOLUTION.md
#
# The previous xhook 1.2.0 static library is kept under third_party/xhook/
# but NOT linked — it remains only as a quick revert path if bytehook
# proves unusable on a specific OEM device.
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
