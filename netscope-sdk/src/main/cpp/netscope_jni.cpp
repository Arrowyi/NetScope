#include <jni.h>
#include <android/log.h>
#include "utils/tls_sni_parser.h"

#define LOG_TAG "NetScope"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// ── Production stubs (will be replaced in Task 8) ────────────────────────────

extern "C" JNIEXPORT jint JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeInit(JNIEnv*, jobject) {
    LOGI("nativeInit stub");
    return 0;
}

// ── Test helpers ──────────────────────────────────────────────────────────────

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testParseSni(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len   = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char sni[256] = {};
    bool ok = netscope::parse_tls_sni(reinterpret_cast<uint8_t*>(data), len, sni, sizeof(sni));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(sni) : nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testParseHttpHost(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len   = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char host[256] = {};
    bool ok = netscope::parse_http_host(reinterpret_cast<uint8_t*>(data), len, host, sizeof(host));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(host) : nullptr;
}
