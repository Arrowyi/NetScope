#pragma once
#include <android/log.h>

#define NETSCOPE_TAG "NetScope"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, NETSCOPE_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  NETSCOPE_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  NETSCOPE_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, NETSCOPE_TAG, __VA_ARGS__)
