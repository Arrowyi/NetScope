cmake_minimum_required(VERSION 3.11)
project(netscopehook C)

set(CMAKE_C_STANDARD 11)

add_library(netscope_hook SHARED
    fd_table.c
    got_patcher.c
    socket_proxy.c
    hook_jni.c
)

# Only system libs — zero third-party hook library dependency.
# No libshadowhook, no libbytehook.
target_link_libraries(netscope_hook
    log   # android/log.h
    dl    # dlfcn.h (dlsym, dl_iterate_phdr)
)
