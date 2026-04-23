cmake_minimum_required(VERSION 3.22.1)
project("netscope")

# xhook: pure GOT/PLT patcher, no mmap(PROT_EXEC), no trampolines.
# Links statically into libnetscope.so — no extra .so shipped to consumers.
add_library(xhook STATIC IMPORTED)
set_target_properties(xhook PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xhook/libs/${ANDROID_ABI}/libxhook.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/third_party/xhook/include
)

add_library(netscope SHARED
    netscope_jni.cpp
    hook/hook_manager.cpp
    hook/hook_connect.cpp
    hook/hook_dns.cpp
    hook/hook_send_recv.cpp
    hook/hook_close.cpp
    hook/libc_funcs.cpp
    hook/got_audit.cpp
    core/dns_cache.cpp
    core/flow_table.cpp
    core/stats_aggregator.cpp
    utils/tls_sni_parser.cpp
    utils/ip_utils.cpp
)

target_include_directories(netscope PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(netscope
    xhook
    log
    android
)
