#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "socket_proxy.h"
#include "fd_table.h"

#define PKG "indi/arrowyi/netscope/hook/NetScopeHook"

/* ── nativeStart ─────────────────────────────────────────────────────────── */

JNIEXPORT jboolean JNICALL
Java_indi_arrowyi_netscope_hook_NetScopeHook_nativeStart(JNIEnv* env, jobject thiz) {
    (void)env; (void)thiz;
    return socket_proxy_install() > 0 ? JNI_TRUE : JNI_FALSE;
}

/* ── nativeStop ──────────────────────────────────────────────────────────── */

JNIEXPORT void JNICALL
Java_indi_arrowyi_netscope_hook_NetScopeHook_nativeStop(JNIEnv* env, jobject thiz) {
    (void)env; (void)thiz;
    socket_proxy_uninstall();
}

/* ── nativeClearStats ────────────────────────────────────────────────────── */

JNIEXPORT void JNICALL
Java_indi_arrowyi_netscope_hook_NetScopeHook_nativeClearStats(JNIEnv* env, jobject thiz) {
    (void)env; (void)thiz;
    fd_table_clear();
}

/* ── nativeGetSocketStats ────────────────────────────────────────────────── */

JNIEXPORT jobject JNICALL
Java_indi_arrowyi_netscope_hook_NetScopeHook_nativeGetSocketStats(JNIEnv* env, jobject thiz) {
    (void)thiz;

    /* Snapshot up to 512 entries from the aggregation table. */
    AggEntry entries[512];
    int count = fd_table_snapshot(entries, 512);

    /* Build ArrayList<SocketStats> */
    jclass list_cls = (*env)->FindClass(env, "java/util/ArrayList");
    jmethodID list_init = (*env)->GetMethodID(env, list_cls, "<init>", "(I)V");
    jmethodID list_add  = (*env)->GetMethodID(env, list_cls, "add", "(Ljava/lang/Object;)Z");
    jobject list = (*env)->NewObject(env, list_cls, list_init, (jint)count);

    jclass stats_cls = (*env)->FindClass(env,
        "indi/arrowyi/netscope/hook/SocketStats");
    jmethodID stats_init = (*env)->GetMethodID(env, stats_cls, "<init>",
        "(Ljava/lang/String;JJI)V");

    for (int i = 0; i < count; i++) {
        jstring addr = (*env)->NewStringUTF(env, entries[i].remote_addr);
        jobject stats = (*env)->NewObject(env, stats_cls, stats_init,
            addr,
            (jlong)entries[i].tx_bytes,
            (jlong)entries[i].rx_bytes,
            (jint)entries[i].conn_count);
        (*env)->CallBooleanMethod(env, list, list_add, stats);
        (*env)->DeleteLocalRef(env, addr);
        (*env)->DeleteLocalRef(env, stats);
    }

    (*env)->DeleteLocalRef(env, list_cls);
    (*env)->DeleteLocalRef(env, stats_cls);
    return list;
}

/* ── nativeGetSocketTotalStats ───────────────────────────────────────────── */

JNIEXPORT jobject JNICALL
Java_indi_arrowyi_netscope_hook_NetScopeHook_nativeGetSocketTotalStats(JNIEnv* env, jobject thiz) {
    (void)thiz;

    int64_t tx = 0, rx = 0; int cn = 0;
    fd_table_total(&tx, &rx, &cn);

    jclass cls = (*env)->FindClass(env,
        "indi/arrowyi/netscope/hook/SocketTotalStats");
    jmethodID init = (*env)->GetMethodID(env, cls, "<init>", "(JJI)V");
    jobject obj = (*env)->NewObject(env, cls, init, (jlong)tx, (jlong)rx, (jint)cn);
    (*env)->DeleteLocalRef(env, cls);
    return obj;
}
