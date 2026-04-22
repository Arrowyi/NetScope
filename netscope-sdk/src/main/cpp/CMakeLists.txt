cmake_minimum_required(VERSION 3.22.1)
project("netscope")

add_library(shadowhook SHARED IMPORTED)
set_target_properties(shadowhook PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/third_party/shadowhook/libs/${ANDROID_ABI}/libshadowhook.so
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR}/third_party/shadowhook/include
)

add_library(netscope SHARED
    netscope_jni.cpp
    hook/hook_manager.cpp
    hook/hook_connect.cpp
    hook/hook_dns.cpp
    hook/hook_send_recv.cpp
    hook/hook_conscrypt.cpp
    hook/hook_close.cpp
    core/dns_cache.cpp
    core/flow_table.cpp
    core/stats_aggregator.cpp
    utils/tls_sni_parser.cpp
    utils/ip_utils.cpp
)

target_include_directories(netscope PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(netscope
    shadowhook
    log
    android
)
