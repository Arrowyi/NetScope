#include <jni.h>
#include <android/log.h>
#include "utils/tls_sni_parser.h"
#include "core/dns_cache.h"

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

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testDnsCacheStore(JNIEnv* env, jobject,
                                                        jstring ip, jstring domain) {
    const char* ip_c = env->GetStringUTFChars(ip, nullptr);
    if (!ip_c) return;
    const char* dom_c = env->GetStringUTFChars(domain, nullptr);
    if (!dom_c) { env->ReleaseStringUTFChars(ip, ip_c); return; }
    netscope::DnsCache::instance().store(ip_c, dom_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    env->ReleaseStringUTFChars(domain, dom_c);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testDnsCacheLookup(JNIEnv* env, jobject, jstring ip) {
    const char* ip_c = env->GetStringUTFChars(ip, nullptr);
    if (!ip_c) return nullptr;
    std::string result = netscope::DnsCache::instance().lookup(ip_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}
