#include <jni.h>
#include <android/log.h>
#include "utils/tls_sni_parser.h"
#include "core/dns_cache.h"
#include "core/flow_table.h"
#include "core/stats_aggregator.h"
#include "hook/hook_manager.h"

#define LOG_TAG "NetScope"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Helper: convert DomainStatsC vector to Java DomainStats[]
// DomainStats constructor: (String domain, long txTotal, long rxTotal,
//                           long txInterval, long rxInterval,
//                           int connTotal, int connInterval, long lastActiveMs)
static jobjectArray make_stats_array(JNIEnv* env, const std::vector<netscope::DomainStatsC>& vec) {
    jclass cls = env->FindClass("indi/arrowyi/sdk/DomainStats");
    if (!cls) return env->NewObjectArray(0, env->FindClass("java/lang/Object"), nullptr);
    jmethodID ctor = env->GetMethodID(cls, "<init>", "(Ljava/lang/String;JJJJIIJ)V");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(vec.size()), cls, nullptr);
    for (size_t i = 0; i < vec.size(); ++i) {
        const auto& s = vec[i];
        jobject obj = env->NewObject(cls, ctor,
            env->NewStringUTF(s.domain),
            static_cast<jlong>(s.tx_total),
            static_cast<jlong>(s.rx_total),
            static_cast<jlong>(s.tx_curr),
            static_cast<jlong>(s.rx_curr),
            static_cast<jint>(s.count_total),
            static_cast<jint>(s.count_curr),
            static_cast<jlong>(s.last_active_ms));
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), obj);
        env->DeleteLocalRef(obj);
    }
    return arr;
}

// For interval stats, the data comes from getIntervalStats() which populates tx_snap/rx_snap
static jobjectArray make_interval_array(JNIEnv* env, const std::vector<netscope::DomainStatsC>& vec) {
    jclass cls = env->FindClass("indi/arrowyi/sdk/DomainStats");
    if (!cls) return env->NewObjectArray(0, env->FindClass("java/lang/Object"), nullptr);
    jmethodID ctor = env->GetMethodID(cls, "<init>", "(Ljava/lang/String;JJJJIIJ)V");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(vec.size()), cls, nullptr);
    for (size_t i = 0; i < vec.size(); ++i) {
        const auto& s = vec[i];
        jobject obj = env->NewObject(cls, ctor,
            env->NewStringUTF(s.domain),
            0LL, 0LL,
            static_cast<jlong>(s.tx_snap),
            static_cast<jlong>(s.rx_snap),
            0,
            static_cast<jint>(s.count_snap),
            0LL);
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), obj);
        env->DeleteLocalRef(obj);
    }
    return arr;
}

// Global JVM reference for callback thread attachment
static JavaVM* g_jvm = nullptr;
static jobject g_callback_obj = nullptr;  // GlobalRef to Kotlin lambda

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jint JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeInit(JNIEnv*, jobject) {
    return netscope::hook_manager_init();
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeDestroy(JNIEnv*, jobject) {
    netscope::hook_manager_destroy();
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativePause(JNIEnv*, jobject) {
    netscope::hook_manager_set_paused(true);
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeResume(JNIEnv*, jobject) {
    netscope::hook_manager_set_paused(false);
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeClearStats(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().clear();
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeMarkIntervalBoundary(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().markIntervalBoundary();
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeGetDomainStats(JNIEnv* env, jobject) {
    return make_stats_array(env, netscope::StatsAggregator::instance().getDomainStats());
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeGetIntervalStats(JNIEnv* env, jobject) {
    return make_interval_array(env, netscope::StatsAggregator::instance().getIntervalStats());
}
extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_nativeSetFlowEndCallback(JNIEnv* env, jobject,
                                                               jobject callback) {
    if (g_callback_obj) { env->DeleteGlobalRef(g_callback_obj); g_callback_obj = nullptr; }
    if (!callback) {
        netscope::StatsAggregator::instance().setFlowEndCallback(nullptr);
        return;
    }
    g_callback_obj = env->NewGlobalRef(callback);
    netscope::StatsAggregator::instance().setFlowEndCallback([](const netscope::DomainStatsC& s) {
        JNIEnv* env2 = nullptr;
        if (!g_jvm || g_jvm->AttachCurrentThread(&env2, nullptr) != JNI_OK) return;
        jclass cls = env2->FindClass("indi/arrowyi/sdk/DomainStats");
        if (!cls) { g_jvm->DetachCurrentThread(); return; }
        jmethodID ctor = env2->GetMethodID(cls, "<init>", "(Ljava/lang/String;JJJJIIJ)V");
        if (!ctor) { env2->DeleteLocalRef(cls); g_jvm->DetachCurrentThread(); return; }
        jobject obj = env2->NewObject(cls, ctor,
            env2->NewStringUTF(s.domain),
            0LL, 0LL,
            static_cast<jlong>(s.tx_curr),
            static_cast<jlong>(s.rx_curr),
            0, 1,
            static_cast<jlong>(s.last_active_ms));
        jclass fn_cls = env2->GetObjectClass(g_callback_obj);
        jmethodID invoke = env2->GetMethodID(fn_cls, "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;");
        if (!invoke) {
            env2->DeleteLocalRef(obj);
            env2->DeleteLocalRef(cls);
            env2->DeleteLocalRef(fn_cls);
            g_jvm->DetachCurrentThread();
            return;
        }
        env2->CallObjectMethod(g_callback_obj, invoke, obj);
        env2->DeleteLocalRef(obj);
        env2->DeleteLocalRef(cls);
        env2->DeleteLocalRef(fn_cls);
        g_jvm->DetachCurrentThread();
    });
}

// ── Test helpers ──────────────────────────────────────────────────────────────

extern "C" JNIEXPORT jstring JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testParseSni(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len   = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char sni[256] = {};
    bool ok = netscope::parse_tls_sni(reinterpret_cast<uint8_t*>(data), len, sni, sizeof(sni));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(sni) : nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testParseHttpHost(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len   = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char host[256] = {};
    bool ok = netscope::parse_http_host(reinterpret_cast<uint8_t*>(data), len, host, sizeof(host));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(host) : nullptr;
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testDnsCacheStore(JNIEnv* env, jobject,
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
Java_indi_arrowyi_sdk_NetScopeNative_testDnsCacheLookup(JNIEnv* env, jobject, jstring ip) {
    const char* ip_c = env->GetStringUTFChars(ip, nullptr);
    if (!ip_c) return nullptr;
    std::string result = netscope::DnsCache::instance().lookup(ip_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testFlowCreate(JNIEnv* env, jobject,
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
Java_indi_arrowyi_sdk_NetScopeNative_testFlowAddTx(JNIEnv*, jobject, jint fd, jlong bytes) {
    netscope::FlowTable::instance().add_tx(fd, bytes);
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testFlowAddRx(JNIEnv*, jobject, jint fd, jlong bytes) {
    netscope::FlowTable::instance().add_rx(fd, bytes);
}

extern "C" JNIEXPORT jstring JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testFlowGetDomain(JNIEnv* env, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return nullptr;
    return env->NewStringUTF(e.domain);
}

extern "C" JNIEXPORT jlong JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testFlowGetTx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return -1;
    return static_cast<jlong>(e.tx_bytes);
}

extern "C" JNIEXPORT jlong JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testFlowGetRx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!netscope::FlowTable::instance().get(fd, &e)) return -1;
    return static_cast<jlong>(e.rx_bytes);
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testStatsClear(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().clear();
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testStatsFlush(JNIEnv* env, jobject,
                                                     jstring domain, jlong tx, jlong rx) {
    const char* d = env->GetStringUTFChars(domain, nullptr);
    if (!d) return;
    netscope::StatsAggregator::instance().flush(d, static_cast<uint64_t>(tx), static_cast<uint64_t>(rx));
    env->ReleaseStringUTFChars(domain, d);
}

extern "C" JNIEXPORT void JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testStatsMark(JNIEnv*, jobject) {
    netscope::StatsAggregator::instance().markIntervalBoundary();
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_indi_arrowyi_sdk_NetScopeNative_testStatsGetCumulative(JNIEnv* env, jobject) {
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
Java_indi_arrowyi_sdk_NetScopeNative_testStatsGetInterval(JNIEnv* env, jobject) {
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
