#include <jni.h>
#include <android/log.h>
#include "utils/tls_sni_parser.h"
#include "core/dns_cache.h"
#include "core/flow_table.h"
#include "core/stats_aggregator.h"

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

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowCreate(JNIEnv* env, jobject,
        jint fd, jstring ip, jint port, jstring domain) {
    const char* ip_c = env->GetStringUTFChars(ip, nullptr);
    if (!ip_c) return;
    const char* dom_c = env->GetStringUTFChars(domain, nullptr);
    if (!dom_c) { env->ReleaseStringUTFChars(ip, ip_c); return; }
    netscope::FlowTable::instance().create(fd, ip_c, static_cast<uint16_t>(port), dom_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    env->ReleaseStringUTFChars(domain, dom_c);
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowAddTx(JNIEnv*, jobject, jint fd, jlong bytes) {
    netscope::FlowTable::instance().add_tx(fd, bytes);
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowAddRx(JNIEnv*, jobject, jint fd, jlong bytes) {
    netscope::FlowTable::instance().add_rx(fd, bytes);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetDomain(JNIEnv* env, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return nullptr;
    return env->NewStringUTF(e.domain);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetTx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return -1;
    return static_cast<jlong>(e.tx_bytes);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetRx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return -1;
    return static_cast<jlong>(e.rx_bytes);
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsClear(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().clear();
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsFlush(JNIEnv* env, jobject,
                                                     jstring domain, jlong tx, jlong rx) {
    const char* d = env->GetStringUTFChars(domain, nullptr);
    if (!d) return;
    netscope::StatsAggregator::instance().flush(d, static_cast<uint64_t>(tx), static_cast<uint64_t>(rx));
    env->ReleaseStringUTFChars(domain, d);
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsMark(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().markIntervalBoundary();
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsGetCumulative(JNIEnv* env, jobject) {
    auto stats = netscope::StatsAggregator::instance().getDomainStats();
    jclass strCls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(stats.size()), strCls, nullptr);
    for (size_t i = 0; i < stats.size(); ++i) {
        char buf[512];
        snprintf(buf, sizeof(buf), "domain=%s tx=%llu rx=%llu",
            stats[i].domain,
            (unsigned long long)stats[i].tx_total,
            (unsigned long long)stats[i].rx_total);
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), env->NewStringUTF(buf));
    }
    return arr;
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsGetInterval(JNIEnv* env, jobject) {
    auto stats = netscope::StatsAggregator::instance().getIntervalStats();
    jclass strCls = env->FindClass("java/lang/String");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(stats.size()), strCls, nullptr);
    for (size_t i = 0; i < stats.size(); ++i) {
        char buf[512];
        snprintf(buf, sizeof(buf), "domain=%s tx=%llu rx=%llu",
            stats[i].domain,
            (unsigned long long)stats[i].tx_snap,
            (unsigned long long)stats[i].rx_snap);
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), env->NewStringUTF(buf));
    }
    return arr;
}
