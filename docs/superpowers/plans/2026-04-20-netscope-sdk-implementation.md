# NetScope SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-ready Android AAR SDK that uses PLT Hook to intercept libc network calls, aggregating per-domain HTTP/HTTPS traffic statistics (TX + RX, cumulative + interval) for the embedding app.

**Architecture:** shadowhook installs PLT hooks on `connect/send/recv/getaddrinfo/close` and family; a C++ core layer (`flow_table`, `dns_cache`, `stats_aggregator`) aggregates data thread-safely; a Kotlin singleton exposes the API with periodic Logcat output.

**Tech Stack:** Android NDK r25c+, C++17, shadowhook 1.0.9, Kotlin 1.9, Gradle 8.2, minSdk 29, ABI arm64-v8a + armeabi-v7a

---

## File Map

```
NetScope/
├── settings.gradle
├── build.gradle
├── netscope-sdk/
│   ├── build.gradle
│   ├── consumer-rules.pro
│   └── src/
│       ├── main/
│       │   ├── AndroidManifest.xml
│       │   ├── cpp/
│       │   │   ├── CMakeLists.txt
│       │   │   ├── netscope_jni.cpp
│       │   │   ├── hook/
│       │   │   │   ├── hook_manager.h / .cpp   ← shadowhook init, install/uninstall all
│       │   │   │   ├── hook_connect.h / .cpp   ← connect() hook
│       │   │   │   ├── hook_dns.h / .cpp       ← getaddrinfo() hook
│       │   │   │   ├── hook_send_recv.h / .cpp ← send/sendto/write/writev/recv/recvfrom/read/readv
│       │   │   │   └── hook_close.h / .cpp     ← close() hook
│       │   │   ├── core/
│       │   │   │   ├── dns_cache.h / .cpp      ← IP→domain map, 60s TTL
│       │   │   │   ├── flow_table.h / .cpp     ← fd→FlowEntry map
│       │   │   │   └── stats_aggregator.h/.cpp ← domain-level totals + interval
│       │   │   └── utils/
│       │   │       ├── tls_sni_parser.h / .cpp ← parse TLS ClientHello SNI
│       │   │       └── ip_utils.h / .cpp       ← inet_ntop wrappers
│       │   └── kotlin/com/netscope/sdk/
│       │       ├── DomainStats.kt
│       │       ├── NetScopeNative.kt
│       │       ├── NetScope.kt
│       │       └── LogcatReporter.kt
│       └── androidTest/kotlin/com/netscope/sdk/
│           └── NetScopeInstrumentedTest.kt
└── app/
    ├── build.gradle
    └── src/main/
        ├── AndroidManifest.xml
        └── kotlin/com/netscope/app/
            └── MainActivity.kt
```

---

## Task 1: Project Scaffold

**Files:**
- Create: `settings.gradle`
- Create: `build.gradle`
- Create: `netscope-sdk/build.gradle`
- Create: `netscope-sdk/consumer-rules.pro`
- Create: `netscope-sdk/src/main/AndroidManifest.xml`
- Create: `app/build.gradle`
- Create: `app/src/main/AndroidManifest.xml`

- [ ] **Step 1: Create `settings.gradle`**

```groovy
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "NetScope"
include ':netscope-sdk'
include ':app'
```

- [ ] **Step 2: Create root `build.gradle`**

```groovy
plugins {
    id 'com.android.application' version '8.2.2' apply false
    id 'com.android.library'     version '8.2.2' apply false
    id 'org.jetbrains.kotlin.android' version '1.9.22' apply false
}
```

- [ ] **Step 3: Create `netscope-sdk/build.gradle`**

```groovy
plugins {
    id 'com.android.library'
    id 'org.jetbrains.kotlin.android'
    id 'maven-publish'
}

android {
    namespace 'com.netscope.sdk'
    compileSdk 34

    defaultConfig {
        minSdk 29
        testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles "consumer-rules.pro"

        externalNativeBuild {
            cmake {
                cppFlags "-std=c++17 -fexceptions -frtti"
                arguments "-DANDROID_STL=c++_shared"
                abiFilters 'arm64-v8a', 'armeabi-v7a'
            }
        }
    }

    buildTypes {
        release { minifyEnabled false }
    }

    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = '1.8' }

    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
            version "3.22.1"
        }
    }

    buildFeatures { prefab true }

    publishing {
        singleVariant('release') { withSourcesJar() }
    }
}

dependencies {
    implementation 'com.bytedance.android.byteHook:shadowhook:1.0.9'
    implementation 'androidx.annotation:annotation:1.7.1'
    testImplementation 'junit:junit:4.13.2'
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
    androidTestImplementation 'com.squareup.okhttp3:okhttp:4.12.0'
}

publishing {
    publications {
        release(MavenPublication) {
            groupId    = 'com.netscope'
            artifactId = 'netscope-sdk'
            version    = '1.0.0'
            afterEvaluate { from components.release }
        }
    }
    repositories {
        maven {
            name = 'localRepo'
            url  = uri("${rootProject.buildDir}/repo")
        }
    }
}
```

- [ ] **Step 4: Create `netscope-sdk/consumer-rules.pro`**

```
-keep class com.netscope.sdk.** { *; }
```

- [ ] **Step 5: Create `netscope-sdk/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" />
```

- [ ] **Step 6: Create `app/build.gradle`**

```groovy
plugins {
    id 'com.android.application'
    id 'org.jetbrains.kotlin.android'
}

android {
    namespace 'com.netscope.app'
    compileSdk 34
    defaultConfig {
        applicationId "com.netscope.app"
        minSdk 29
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    buildTypes { release { minifyEnabled false } }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
    kotlinOptions { jvmTarget = '1.8' }
    buildFeatures { viewBinding true }
}

dependencies {
    implementation project(':netscope-sdk')
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.squareup.okhttp3:okhttp:4.12.0'
}
```

- [ ] **Step 7: Create `app/src/main/AndroidManifest.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
    <application
        android:name=".SampleApplication"
        android:label="NetScope Sample"
        android:theme="@style/Theme.AppCompat">
        <activity android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

- [ ] **Step 8: Download Gradle wrapper and verify sync**

```bash
cd /Users/bdgong/WorkSpace/GitRepositories/NetScope
gradle wrapper --gradle-version=8.2.1
./gradlew projects
```

Expected output: includes `:netscope-sdk` and `:app`

- [ ] **Step 9: Commit**

```bash
git add .
git commit -m "build: project scaffold with SDK and sample app modules"
```

---

## Task 2: CMake Build Setup

**Files:**
- Create: `netscope-sdk/src/main/cpp/CMakeLists.txt`
- Create: `netscope-sdk/src/main/cpp/netscope_jni.cpp` (stub)

- [ ] **Step 1: Create `CMakeLists.txt`**

```cmake
cmake_minimum_required(VERSION 3.22.1)
project("netscope")

find_package(shadowhook REQUIRED CONFIG)

add_library(netscope SHARED
    netscope_jni.cpp
    hook/hook_manager.cpp
    hook/hook_connect.cpp
    hook/hook_dns.cpp
    hook/hook_send_recv.cpp
    hook/hook_close.cpp
    core/dns_cache.cpp
    core/flow_table.cpp
    core/stats_aggregator.cpp
    utils/tls_sni_parser.cpp
    utils/ip_utils.cpp
)

target_include_directories(netscope PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(netscope
    shadowhook::shadowhook
    log
    android
)
```

- [ ] **Step 2: Create stub `netscope_jni.cpp` that compiles cleanly**

```cpp
#include <jni.h>
#include <android/log.h>
#define LOG_TAG "NetScope"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jint JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeInit(JNIEnv*, jobject) {
    LOGI("nativeInit stub");
    return 0;
}
```

- [ ] **Step 3: Create all stub `.cpp` files so CMake finds every listed source**

Create each file with a single empty comment `// stub`:

```
netscope-sdk/src/main/cpp/hook/hook_manager.cpp
netscope-sdk/src/main/cpp/hook/hook_manager.h
netscope-sdk/src/main/cpp/hook/hook_connect.cpp
netscope-sdk/src/main/cpp/hook/hook_connect.h
netscope-sdk/src/main/cpp/hook/hook_dns.cpp
netscope-sdk/src/main/cpp/hook/hook_dns.h
netscope-sdk/src/main/cpp/hook/hook_send_recv.cpp
netscope-sdk/src/main/cpp/hook/hook_send_recv.h
netscope-sdk/src/main/cpp/hook/hook_close.cpp
netscope-sdk/src/main/cpp/hook/hook_close.h
netscope-sdk/src/main/cpp/core/dns_cache.cpp
netscope-sdk/src/main/cpp/core/dns_cache.h
netscope-sdk/src/main/cpp/core/flow_table.cpp
netscope-sdk/src/main/cpp/core/flow_table.h
netscope-sdk/src/main/cpp/core/stats_aggregator.cpp
netscope-sdk/src/main/cpp/core/stats_aggregator.h
netscope-sdk/src/main/cpp/utils/tls_sni_parser.cpp
netscope-sdk/src/main/cpp/utils/tls_sni_parser.h
netscope-sdk/src/main/cpp/utils/ip_utils.cpp
netscope-sdk/src/main/cpp/utils/ip_utils.h
```

- [ ] **Step 4: Verify native build compiles**

```bash
./gradlew :netscope-sdk:assembleDebug
```

Expected: BUILD SUCCESSFUL, `libnetscope.so` present in build outputs.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "build: cmake setup with shadowhook prefab, stub sources compile"
```

---

## Task 3: utils/ — ip_utils + tls_sni_parser

**Files:**
- Modify: `netscope-sdk/src/main/cpp/utils/ip_utils.h`
- Modify: `netscope-sdk/src/main/cpp/utils/ip_utils.cpp`
- Modify: `netscope-sdk/src/main/cpp/utils/tls_sni_parser.h`
- Modify: `netscope-sdk/src/main/cpp/utils/tls_sni_parser.cpp`
- Create: `netscope-sdk/src/main/cpp/netscope_jni.cpp` (add test JNI functions)
- Create: `netscope-sdk/src/androidTest/kotlin/com/netscope/sdk/NetScopeInstrumentedTest.kt`

- [ ] **Step 1: Write failing test for SNI parser**

Create `netscope-sdk/src/androidTest/kotlin/com/netscope/sdk/NetScopeInstrumentedTest.kt`:

```kotlin
package com.netscope.sdk

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NetScopeInstrumentedTest {

    // TLS ClientHello with SNI = "api.example.com"
    // Minimal synthetic packet built from spec
    private val TLS_CLIENT_HELLO_SNI = byteArrayOf(
        0x16.toByte(), 0x03, 0x01,       // TLS Handshake, TLS 1.0
        0x00, 0x3f,                        // record length = 63
        0x01,                              // ClientHello
        0x00, 0x00, 0x3b,                  // handshake length = 59
        0x03, 0x03,                        // client version TLS 1.2
        // Random: 32 bytes
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,                              // session ID length = 0
        0x00, 0x02,                        // cipher suites length = 2
        0x00, 0x2f,                        // TLS_RSA_WITH_AES_128_CBC_SHA
        0x01, 0x00,                        // compression methods length=1, null
        0x00, 0x13,                        // extensions length = 19
        // SNI extension
        0x00, 0x00,                        // extension type = 0 (SNI)
        0x00, 0x0f,                        // extension data length = 15
        0x00, 0x0d,                        // server name list length = 13
        0x00,                              // name type = host_name
        0x00, 0x0a,                        // name length = 10
        // "api.test.c" — NOTE: deliberately short to fit length math above
        0x61, 0x70, 0x69, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63
    )

    @Test
    fun testParseTlsSni() {
        System.loadLibrary("netscope")
        val sni = NetScopeNative.testParseSni(TLS_CLIENT_HELLO_SNI)
        assertEquals("api.test.c", sni)
    }

    @Test
    fun testParseTlsSniReturnNullForNonTls() {
        System.loadLibrary("netscope")
        val sni = NetScopeNative.testParseSni("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        assertNull(sni)
    }

    @Test
    fun testParseHttpHost() {
        System.loadLibrary("netscope")
        val host = NetScopeNative.testParseHttpHost("GET / HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n".toByteArray())
        assertEquals("api.example.com", host)
    }

    @Test
    fun testParseHttpHostWithPort() {
        System.loadLibrary("netscope")
        val host = NetScopeNative.testParseHttpHost("POST /path HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n".toByteArray())
        assertEquals("api.example.com", host)
    }
}
```

- [ ] **Step 2: Add test JNI declarations to `NetScopeNative.kt` stub**

Create `netscope-sdk/src/main/kotlin/com/netscope/sdk/NetScopeNative.kt`:

```kotlin
package com.netscope.sdk

internal object NetScopeNative {
    external fun nativeInit(): Int

    // Test helpers (always compiled in; overhead is negligible)
    external fun testParseSni(buf: ByteArray): String?
    external fun testParseHttpHost(buf: ByteArray): String?
}
```

- [ ] **Step 3: Run test — expect FAIL (symbol not found)**

```bash
./gradlew :netscope-sdk:connectedAndroidTest --tests "*.testParseTlsSni"
```

Expected: `UnsatisfiedLinkError` or similar — test infrastructure is wired up correctly.

- [ ] **Step 4: Implement `utils/ip_utils.h`**

```cpp
#pragma once
#include <cstdint>
#include <netinet/in.h>

namespace netscope {

// sockaddr → "1.2.3.4" or "::1"; returns false if not AF_INET/AF_INET6
bool sockaddr_to_ip(const struct sockaddr* addr, char* out_ip, size_t len, uint16_t* out_port);

} // namespace netscope
```

- [ ] **Step 5: Implement `utils/ip_utils.cpp`**

```cpp
#include "ip_utils.h"
#include <arpa/inet.h>
#include <cstring>

namespace netscope {

bool sockaddr_to_ip(const struct sockaddr* addr, char* out_ip, size_t len, uint16_t* out_port) {
    if (!addr) return false;
    if (addr->sa_family == AF_INET) {
        auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        if (!inet_ntop(AF_INET, &a4->sin_addr, out_ip, static_cast<socklen_t>(len))) return false;
        if (out_port) *out_port = ntohs(a4->sin_port);
        return true;
    }
    if (addr->sa_family == AF_INET6) {
        auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (!inet_ntop(AF_INET6, &a6->sin6_addr, out_ip, static_cast<socklen_t>(len))) return false;
        if (out_port) *out_port = ntohs(a6->sin6_port);
        return true;
    }
    return false;
}

} // namespace netscope
```

- [ ] **Step 6: Implement `utils/tls_sni_parser.h`**

```cpp
#pragma once
#include <cstddef>
#include <cstdint>

namespace netscope {

// Returns true and fills out_sni if buf begins with a TLS ClientHello containing an SNI extension.
bool parse_tls_sni(const uint8_t* buf, size_t len, char* out_sni, size_t sni_max_len);

// Returns true and fills out_host if buf begins with an HTTP request containing a Host header.
// Strips the port suffix (":8080") if present.
bool parse_http_host(const uint8_t* buf, size_t len, char* out_host, size_t host_max_len);

} // namespace netscope
```

- [ ] **Step 7: Implement `utils/tls_sni_parser.cpp`**

```cpp
#include "tls_sni_parser.h"
#include <algorithm>
#include <cstring>

namespace netscope {

bool parse_tls_sni(const uint8_t* buf, size_t len, char* out_sni, size_t sni_max_len) {
    // Minimum: 5 (record hdr) + 4 (handshake hdr) + 2 (version) + 32 (random) = 43
    if (len < 43) return false;
    if (buf[0] != 0x16)  return false;  // Content-Type: Handshake
    if (buf[5] != 0x01)  return false;  // HandshakeType: ClientHello

    size_t pos = 43;  // past fixed-length header up through Random

    // Session ID
    if (pos >= len) return false;
    uint8_t sid_len = buf[pos++];
    if (pos + sid_len > len) return false;
    pos += sid_len;

    // Cipher Suites
    if (pos + 2 > len) return false;
    uint16_t cs_len = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    if (pos + cs_len > len) return false;
    pos += cs_len;

    // Compression Methods
    if (pos + 1 > len) return false;
    uint8_t cm_len = buf[pos++];
    if (pos + cm_len > len) return false;
    pos += cm_len;

    // Extensions
    if (pos + 2 > len) return false;
    uint16_t exts_len = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
    pos += 2;
    size_t exts_end = pos + exts_len;

    while (pos + 4 <= exts_end && pos + 4 <= len) {
        uint16_t ext_type = (static_cast<uint16_t>(buf[pos]) << 8) | buf[pos + 1];
        uint16_t ext_len  = (static_cast<uint16_t>(buf[pos + 2]) << 8) | buf[pos + 3];
        pos += 4;

        if (ext_type == 0x0000) {  // SNI extension
            // server_name_list_length (2) + name_type (1) + name_length (2) + name
            if (pos + 5 > len) return false;
            uint16_t name_len = (static_cast<uint16_t>(buf[pos + 3]) << 8) | buf[pos + 4];
            pos += 5;
            if (pos + name_len > len) return false;
            size_t copy_len = std::min(static_cast<size_t>(name_len), sni_max_len - 1);
            memcpy(out_sni, buf + pos, copy_len);
            out_sni[copy_len] = '\0';
            return copy_len > 0;
        }
        if (pos + ext_len > len) return false;
        pos += ext_len;
    }
    return false;
}

bool parse_http_host(const uint8_t* buf, size_t len, char* out_host, size_t host_max_len) {
    const char* data = reinterpret_cast<const char*>(buf);
    size_t search_len = std::min(len, static_cast<size_t>(4096));

    for (size_t i = 0; i + 6 < search_len; ++i) {
        if ((data[i]   == 'H' || data[i]   == 'h') &&
            (data[i+1] == 'O' || data[i+1] == 'o') &&
            (data[i+2] == 'S' || data[i+2] == 's') &&
            (data[i+3] == 'T' || data[i+3] == 't') &&
             data[i+4] == ':') {
            size_t start = i + 5;
            while (start < search_len && data[start] == ' ') ++start;
            size_t end = start;
            while (end < search_len && data[end] != '\r' && data[end] != '\n') ++end;
            // Strip port
            size_t colon = end;
            for (size_t j = start; j < end; ++j) {
                if (data[j] == ':') { colon = j; break; }
            }
            size_t copy_len = std::min(colon - start, host_max_len - 1);
            if (copy_len == 0) return false;
            memcpy(out_host, data + start, copy_len);
            out_host[copy_len] = '\0';
            return true;
        }
    }
    return false;
}

} // namespace netscope
```

- [ ] **Step 8: Add test JNI functions to `netscope_jni.cpp`**

```cpp
#include <jni.h>
#include <android/log.h>
#include "utils/tls_sni_parser.h"

#define LOG_TAG "NetScope"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jint JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeInit(JNIEnv*, jobject) {
    LOGI("nativeInit stub");
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testParseSni(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char sni[256] = {};
    bool ok = netscope::parse_tls_sni(reinterpret_cast<uint8_t*>(data), len, sni, sizeof(sni));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(sni) : nullptr;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testParseHttpHost(JNIEnv* env, jobject, jbyteArray buf) {
    jsize len = env->GetArrayLength(buf);
    jbyte* data = env->GetByteArrayElements(buf, nullptr);
    char host[256] = {};
    bool ok = netscope::parse_http_host(reinterpret_cast<uint8_t*>(data), len, host, sizeof(host));
    env->ReleaseByteArrayElements(buf, data, JNI_ABORT);
    return ok ? env->NewStringUTF(host) : nullptr;
}
```

- [ ] **Step 9: Run tests — expect PASS**

```bash
./gradlew :netscope-sdk:connectedAndroidTest \
    --tests "com.netscope.sdk.NetScopeInstrumentedTest.testParseTlsSni" \
    --tests "com.netscope.sdk.NetScopeInstrumentedTest.testParseTlsSniReturnNullForNonTls" \
    --tests "com.netscope.sdk.NetScopeInstrumentedTest.testParseHttpHost" \
    --tests "com.netscope.sdk.NetScopeInstrumentedTest.testParseHttpHostWithPort"
```

Expected: 4 tests PASSED

- [ ] **Step 10: Commit**

```bash
git add .
git commit -m "feat: ip_utils and tls_sni_parser with passing instrumented tests"
```

---

## Task 4: core/dns_cache

**Files:**
- Modify: `netscope-sdk/src/main/cpp/core/dns_cache.h`
- Modify: `netscope-sdk/src/main/cpp/core/dns_cache.cpp`
- Modify: `netscope-sdk/src/main/cpp/netscope_jni.cpp` (add test JNI)
- Modify: `netscope-sdk/src/main/kotlin/com/netscope/sdk/NetScopeNative.kt` (add test declarations)
- Modify: `netscope-sdk/src/androidTest/.../NetScopeInstrumentedTest.kt` (add tests)

- [ ] **Step 1: Write failing tests for dns_cache**

Add to `NetScopeInstrumentedTest.kt`:

```kotlin
@Test
fun testDnsCacheStoreAndLookup() {
    System.loadLibrary("netscope")
    NetScopeNative.testDnsCacheStore("192.168.1.1", "api.example.com")
    val domain = NetScopeNative.testDnsCacheLookup("192.168.1.1")
    assertEquals("api.example.com", domain)
}

@Test
fun testDnsCacheMiss() {
    System.loadLibrary("netscope")
    val domain = NetScopeNative.testDnsCacheLookup("10.0.0.99")
    assertNull(domain)
}

@Test
fun testDnsCacheMultipleIps() {
    System.loadLibrary("netscope")
    NetScopeNative.testDnsCacheStore("1.1.1.1", "cdn.example.com")
    NetScopeNative.testDnsCacheStore("1.1.1.2", "cdn.example.com")
    assertEquals("cdn.example.com", NetScopeNative.testDnsCacheLookup("1.1.1.1"))
    assertEquals("cdn.example.com", NetScopeNative.testDnsCacheLookup("1.1.1.2"))
}
```

Add to `NetScopeNative.kt`:

```kotlin
external fun testDnsCacheStore(ip: String, domain: String)
external fun testDnsCacheLookup(ip: String): String?
```

- [ ] **Step 2: Implement `core/dns_cache.h`**

```cpp
#pragma once
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

namespace netscope {

class DnsCache {
public:
    static DnsCache& instance();

    // Store hostname → all resolved IPs
    void store(const std::string& ip, const std::string& hostname);

    // Returns hostname for ip, or empty string on miss/expiry
    std::string lookup(const std::string& ip);

    void clear();

private:
    DnsCache() = default;

    static constexpr int64_t TTL_MS = 60'000;

    struct Entry {
        std::string hostname;
        int64_t     expire_ms;
    };

    std::unordered_map<std::string, Entry> cache_;
    std::shared_mutex mutex_;

    static int64_t now_ms();
};

} // namespace netscope
```

- [ ] **Step 3: Implement `core/dns_cache.cpp`**

```cpp
#include "dns_cache.h"
#include <chrono>

namespace netscope {

DnsCache& DnsCache::instance() {
    static DnsCache inst;
    return inst;
}

int64_t DnsCache::now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void DnsCache::store(const std::string& ip, const std::string& hostname) {
    if (ip.empty() || hostname.empty()) return;
    std::unique_lock lock(mutex_);
    cache_[ip] = {hostname, now_ms() + TTL_MS};
}

std::string DnsCache::lookup(const std::string& ip) {
    std::shared_lock lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) return {};
    if (it->second.expire_ms < now_ms()) return {};
    return it->second.hostname;
}

void DnsCache::clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
}

} // namespace netscope
```

- [ ] **Step 4: Add JNI test functions to `netscope_jni.cpp`**

Append below existing functions:

```cpp
#include "core/dns_cache.h"
using netscope::DnsCache;

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testDnsCacheStore(JNIEnv* env, jobject,
                                                        jstring ip, jstring domain) {
    const char* ip_c  = env->GetStringUTFChars(ip, nullptr);
    const char* dom_c = env->GetStringUTFChars(domain, nullptr);
    DnsCache::instance().store(ip_c, dom_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    env->ReleaseStringUTFChars(domain, dom_c);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testDnsCacheLookup(JNIEnv* env, jobject, jstring ip) {
    const char* ip_c = env->GetStringUTFChars(ip, nullptr);
    std::string result = DnsCache::instance().lookup(ip_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    return result.empty() ? nullptr : env->NewStringUTF(result.c_str());
}
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
./gradlew :netscope-sdk:connectedAndroidTest \
    --tests "*.testDnsCacheStoreAndLookup" \
    --tests "*.testDnsCacheMiss" \
    --tests "*.testDnsCacheMultipleIps"
```

Expected: 3 tests PASSED

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: dns_cache with TTL, passing instrumented tests"
```

---

## Task 5: core/flow_table

**Files:**
- Modify: `core/flow_table.h`, `core/flow_table.cpp`
- Modify: `netscope_jni.cpp`, `NetScopeNative.kt`, `NetScopeInstrumentedTest.kt`

- [ ] **Step 1: Write failing tests**

Add to `NetScopeInstrumentedTest.kt`:

```kotlin
@Test
fun testFlowTableCreateAndGetDomain() {
    System.loadLibrary("netscope")
    NetScopeNative.testFlowCreate(42, "93.184.216.34", 443, "example.com")
    assertEquals("example.com", NetScopeNative.testFlowGetDomain(42))
}

@Test
fun testFlowTableAddBytes() {
    System.loadLibrary("netscope")
    NetScopeNative.testFlowCreate(43, "1.2.3.4", 443, "test.com")
    NetScopeNative.testFlowAddTx(43, 1024)
    NetScopeNative.testFlowAddRx(43, 2048)
    assertEquals(1024L, NetScopeNative.testFlowGetTx(43))
    assertEquals(2048L, NetScopeNative.testFlowGetRx(43))
}

@Test
fun testFlowTableMissingFd() {
    System.loadLibrary("netscope")
    assertNull(NetScopeNative.testFlowGetDomain(9999))
}
```

Add to `NetScopeNative.kt`:

```kotlin
external fun testFlowCreate(fd: Int, ip: String, port: Int, domain: String)
external fun testFlowAddTx(fd: Int, bytes: Long)
external fun testFlowAddRx(fd: Int, bytes: Long)
external fun testFlowGetDomain(fd: Int): String?
external fun testFlowGetTx(fd: Int): Long
external fun testFlowGetRx(fd: Int): Long
```

- [ ] **Step 2: Implement `core/flow_table.h`**

```cpp
#pragma once
#include <string>
#include <unordered_map>
#include <shared_mutex>
#include <cstdint>

namespace netscope {

struct FlowEntry {
    int      fd;
    char     remote_ip[64];
    uint16_t remote_port;
    char     domain[256];
    uint64_t tx_bytes      = 0;
    uint64_t rx_bytes      = 0;
    bool     domain_from_sni = false;  // SNI/Host already resolved → skip DNS override
    bool     first_send_done = false;
};

class FlowTable {
public:
    static FlowTable& instance();

    void   create(int fd, const char* ip, uint16_t port, const char* domain);
    bool   contains(int fd);
    void   add_tx(int fd, uint64_t bytes);
    void   add_rx(int fd, uint64_t bytes);
    // Update domain only if not yet resolved via SNI/Host
    void   set_domain(int fd, const char* domain, bool from_sni);
    void   set_first_send_done(int fd);
    bool   is_first_send_done(int fd);
    // Remove and return entry (for flush on close)
    bool   remove(int fd, FlowEntry* out);

private:
    FlowTable() = default;
    std::unordered_map<int, FlowEntry> table_;
    std::shared_mutex mutex_;
};

} // namespace netscope
```

- [ ] **Step 3: Implement `core/flow_table.cpp`**

```cpp
#include "flow_table.h"
#include <cstring>

namespace netscope {

FlowTable& FlowTable::instance() {
    static FlowTable inst;
    return inst;
}

void FlowTable::create(int fd, const char* ip, uint16_t port, const char* domain) {
    std::unique_lock lock(mutex_);
    FlowEntry e{};
    e.fd = fd;
    strncpy(e.remote_ip,   ip,     sizeof(e.remote_ip) - 1);
    strncpy(e.domain,      domain, sizeof(e.domain) - 1);
    e.remote_port = port;
    table_[fd] = e;
}

bool FlowTable::contains(int fd) {
    std::shared_lock lock(mutex_);
    return table_.count(fd) > 0;
}

void FlowTable::add_tx(int fd, uint64_t bytes) {
    std::shared_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.tx_bytes += bytes;
}

void FlowTable::add_rx(int fd, uint64_t bytes) {
    std::shared_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.rx_bytes += bytes;
}

void FlowTable::set_domain(int fd, const char* domain, bool from_sni) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it == table_.end()) return;
    if (it->second.domain_from_sni && !from_sni) return; // don't downgrade
    strncpy(it->second.domain, domain, sizeof(it->second.domain) - 1);
    it->second.domain_from_sni = from_sni;
}

void FlowTable::set_first_send_done(int fd) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it != table_.end()) it->second.first_send_done = true;
}

bool FlowTable::is_first_send_done(int fd) {
    std::shared_lock lock(mutex_);
    auto it = table_.find(fd);
    return it != table_.end() && it->second.first_send_done;
}

bool FlowTable::remove(int fd, FlowEntry* out) {
    std::unique_lock lock(mutex_);
    auto it = table_.find(fd);
    if (it == table_.end()) return false;
    if (out) *out = it->second;
    table_.erase(it);
    return true;
}

} // namespace netscope
```

- [ ] **Step 4: Add JNI test functions to `netscope_jni.cpp`**

```cpp
#include "core/flow_table.h"
using netscope::FlowTable;

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowCreate(JNIEnv* env, jobject,
        jint fd, jstring ip, jint port, jstring domain) {
    auto* ip_c  = env->GetStringUTFChars(ip, nullptr);
    auto* dom_c = env->GetStringUTFChars(domain, nullptr);
    FlowTable::instance().create(fd, ip_c, static_cast<uint16_t>(port), dom_c);
    env->ReleaseStringUTFChars(ip, ip_c);
    env->ReleaseStringUTFChars(domain, dom_c);
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowAddTx(JNIEnv*, jobject, jint fd, jlong bytes) {
    FlowTable::instance().add_tx(fd, bytes);
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowAddRx(JNIEnv*, jobject, jint fd, jlong bytes) {
    FlowTable::instance().add_rx(fd, bytes);
}
extern "C" JNIEXPORT jstring JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetDomain(JNIEnv* env, jobject, jint fd) {
    netscope::FlowEntry e{};
    // peek without removing
    if (!FlowTable::instance().contains(fd)) return nullptr;
    // use a remove+recreate trick for peek
    if (!FlowTable::instance().remove(fd, &e)) return nullptr;
    FlowTable::instance().create(fd, e.remote_ip, e.remote_port, e.domain);
    return env->NewStringUTF(e.domain);
}
extern "C" JNIEXPORT jlong JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetTx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!FlowTable::instance().remove(fd, &e)) return -1;
    FlowTable::instance().create(fd, e.remote_ip, e.remote_port, e.domain);
    FlowTable::instance().add_tx(fd, e.tx_bytes);
    return static_cast<jlong>(e.tx_bytes);
}
extern "C" JNIEXPORT jlong JNICALL
Java_com_netscope_sdk_NetScopeNative_testFlowGetRx(JNIEnv*, jobject, jint fd) {
    netscope::FlowEntry e{};
    if (!FlowTable::instance().remove(fd, &e)) return -1;
    FlowTable::instance().create(fd, e.remote_ip, e.remote_port, e.domain);
    FlowTable::instance().add_rx(fd, e.rx_bytes);
    return static_cast<jlong>(e.rx_bytes);
}
```

- [ ] **Step 5: Run tests**

```bash
./gradlew :netscope-sdk:connectedAndroidTest \
    --tests "*.testFlowTableCreateAndGetDomain" \
    --tests "*.testFlowTableAddBytes" \
    --tests "*.testFlowTableMissingFd"
```

Expected: 3 PASSED

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: flow_table with thread-safe FlowEntry tracking"
```

---

## Task 6: core/stats_aggregator

**Files:**
- Modify: `core/stats_aggregator.h`, `core/stats_aggregator.cpp`
- Modify: `netscope_jni.cpp`, `NetScopeNative.kt`, `NetScopeInstrumentedTest.kt`

- [ ] **Step 1: Write failing tests**

Add to `NetScopeInstrumentedTest.kt`:

```kotlin
@Test
fun testStatsAggregatorCumulative() {
    System.loadLibrary("netscope")
    NetScopeNative.testStatsClear()
    NetScopeNative.testStatsFlush("api.example.com", 1000L, 2000L)
    NetScopeNative.testStatsFlush("api.example.com", 500L, 300L)
    val stats = NetScopeNative.testStatsGetCumulative()
    val entry = stats.firstOrNull { it.contains("api.example.com") }
    assertNotNull(entry)
    assertTrue(entry!!.contains("tx=1500"))
    assertTrue(entry.contains("rx=2300"))
}

@Test
fun testStatsAggregatorInterval() {
    System.loadLibrary("netscope")
    NetScopeNative.testStatsClear()
    NetScopeNative.testStatsFlush("cdn.example.com", 400L, 800L)
    NetScopeNative.testStatsMark()  // mark boundary
    NetScopeNative.testStatsFlush("cdn.example.com", 100L, 200L)  // new interval
    val snap = NetScopeNative.testStatsGetInterval()  // last completed interval
    val entry = snap.firstOrNull { it.contains("cdn.example.com") }
    assertNotNull(entry)
    assertTrue(entry!!.contains("tx=400"))  // snapshot had 400, not 100
}
```

Add to `NetScopeNative.kt`:

```kotlin
external fun testStatsClear()
external fun testStatsFlush(domain: String, tx: Long, rx: Long)
external fun testStatsMark()
external fun testStatsGetCumulative(): Array<String>
external fun testStatsGetInterval(): Array<String>
```

- [ ] **Step 2: Implement `core/stats_aggregator.h`**

```cpp
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <cstdint>
#include <functional>

namespace netscope {

struct DomainStatsC {
    char     domain[256];
    uint64_t tx_total;
    uint64_t rx_total;
    uint32_t count_total;
    uint64_t tx_curr;      // since last markIntervalBoundary
    uint64_t rx_curr;
    uint32_t count_curr;
    uint64_t tx_snap;      // last completed interval snapshot
    uint64_t rx_snap;
    uint32_t count_snap;
    int64_t  last_active_ms;
};

class StatsAggregator {
public:
    static StatsAggregator& instance();

    void flush(const std::string& domain, uint64_t tx, uint64_t rx);
    void markIntervalBoundary();
    void clear();

    // Fills out with all tracked domains
    std::vector<DomainStatsC> getDomainStats();
    std::vector<DomainStatsC> getIntervalStats();  // last completed interval only

    // Called when a flow ends (for setOnFlowEnd callback)
    using FlowEndCallback = std::function<void(const DomainStatsC&)>;
    void setFlowEndCallback(FlowEndCallback cb);
    void invokeFlowEndCallback(const std::string& domain, uint64_t tx, uint64_t rx);

private:
    StatsAggregator() = default;
    static int64_t now_ms();

    struct Record {
        std::atomic<uint64_t> tx_total{0};
        std::atomic<uint64_t> rx_total{0};
        std::atomic<uint32_t> count_total{0};
        std::atomic<uint64_t> tx_curr{0};
        std::atomic<uint64_t> rx_curr{0};
        std::atomic<uint32_t> count_curr{0};
        std::atomic<int64_t>  last_active_ms{0};
    };

    struct Snap {
        uint64_t tx; uint64_t rx; uint32_t count;
    };

    // records_mutex_ guards insertions into records_ map; atomic fields within Record
    // are updated without the lock after the record exists
    std::shared_mutex records_mutex_;
    std::unordered_map<std::string, Record> records_;

    std::mutex snap_mutex_;
    std::unordered_map<std::string, Snap> snapshot_;

    std::mutex cb_mutex_;
    FlowEndCallback flow_end_cb_;
};

} // namespace netscope
```

- [ ] **Step 3: Implement `core/stats_aggregator.cpp`**

```cpp
#include "stats_aggregator.h"
#include <chrono>
#include <cstring>

namespace netscope {

StatsAggregator& StatsAggregator::instance() {
    static StatsAggregator inst;
    return inst;
}

int64_t StatsAggregator::now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void StatsAggregator::flush(const std::string& domain, uint64_t tx, uint64_t rx) {
    if (domain.empty()) return;
    {
        // Fast path: record exists, update atomics without write lock
        std::shared_lock rlock(records_mutex_);
        auto it = records_.find(domain);
        if (it != records_.end()) {
            it->second.tx_total    += tx;
            it->second.rx_total    += rx;
            it->second.count_total += 1;
            it->second.tx_curr     += tx;
            it->second.rx_curr     += rx;
            it->second.count_curr  += 1;
            it->second.last_active_ms.store(now_ms());
            return;
        }
    }
    // Slow path: new domain
    std::unique_lock wlock(records_mutex_);
    auto& r = records_[domain];
    r.tx_total    = tx;
    r.rx_total    = rx;
    r.count_total = 1;
    r.tx_curr     = tx;
    r.rx_curr     = rx;
    r.count_curr  = 1;
    r.last_active_ms = now_ms();
}

void StatsAggregator::markIntervalBoundary() {
    std::shared_lock rlock(records_mutex_);
    std::lock_guard<std::mutex> slock(snap_mutex_);
    snapshot_.clear();
    for (auto& [domain, r] : records_) {
        snapshot_[domain] = {
            r.tx_curr.exchange(0),
            r.rx_curr.exchange(0),
            r.count_curr.exchange(0)
        };
    }
}

void StatsAggregator::clear() {
    std::unique_lock wlock(records_mutex_);
    records_.clear();
    std::lock_guard<std::mutex> slock(snap_mutex_);
    snapshot_.clear();
}

std::vector<DomainStatsC> StatsAggregator::getDomainStats() {
    std::shared_lock rlock(records_mutex_);
    std::vector<DomainStatsC> result;
    result.reserve(records_.size());
    for (auto& [domain, r] : records_) {
        DomainStatsC s{};
        strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
        s.tx_total      = r.tx_total.load();
        s.rx_total      = r.rx_total.load();
        s.count_total   = r.count_total.load();
        s.tx_curr       = r.tx_curr.load();
        s.rx_curr       = r.rx_curr.load();
        s.count_curr    = r.count_curr.load();
        s.last_active_ms = r.last_active_ms.load();
        result.push_back(s);
    }
    return result;
}

std::vector<DomainStatsC> StatsAggregator::getIntervalStats() {
    std::lock_guard<std::mutex> slock(snap_mutex_);
    std::vector<DomainStatsC> result;
    for (auto& [domain, snap] : snapshot_) {
        if (snap.tx == 0 && snap.rx == 0) continue;
        DomainStatsC s{};
        strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
        s.tx_snap    = snap.tx;
        s.rx_snap    = snap.rx;
        s.count_snap = snap.count;
        result.push_back(s);
    }
    return result;
}

void StatsAggregator::setFlowEndCallback(FlowEndCallback cb) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    flow_end_cb_ = std::move(cb);
}

void StatsAggregator::invokeFlowEndCallback(const std::string& domain, uint64_t tx, uint64_t rx) {
    std::lock_guard<std::mutex> lock(cb_mutex_);
    if (!flow_end_cb_) return;
    DomainStatsC s{};
    strncpy(s.domain, domain.c_str(), sizeof(s.domain) - 1);
    s.tx_curr = tx;
    s.rx_curr = rx;
    flow_end_cb_(s);
}

} // namespace netscope
```

- [ ] **Step 4: Add JNI test functions to `netscope_jni.cpp`**

```cpp
#include "core/stats_aggregator.h"
using netscope::StatsAggregator;

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsClear(JNIEnv*, jobject) {
    StatsAggregator::instance().clear();
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsFlush(JNIEnv* env, jobject,
                                                     jstring domain, jlong tx, jlong rx) {
    auto* d = env->GetStringUTFChars(domain, nullptr);
    StatsAggregator::instance().flush(d, tx, rx);
    env->ReleaseStringUTFChars(domain, d);
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsMark(JNIEnv*, jobject) {
    StatsAggregator::instance().markIntervalBoundary();
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsGetCumulative(JNIEnv* env, jobject) {
    auto stats = StatsAggregator::instance().getDomainStats();
    jobjectArray arr = env->NewObjectArray(stats.size(),
        env->FindClass("java/lang/String"), nullptr);
    for (size_t i = 0; i < stats.size(); ++i) {
        char buf[512];
        snprintf(buf, sizeof(buf), "domain=%s tx=%llu rx=%llu",
            stats[i].domain,
            (unsigned long long)stats[i].tx_total,
            (unsigned long long)stats[i].rx_total);
        env->SetObjectArrayElement(arr, i, env->NewStringUTF(buf));
    }
    return arr;
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_testStatsGetInterval(JNIEnv* env, jobject) {
    auto stats = StatsAggregator::instance().getIntervalStats();
    jobjectArray arr = env->NewObjectArray(stats.size(),
        env->FindClass("java/lang/String"), nullptr);
    for (size_t i = 0; i < stats.size(); ++i) {
        char buf[512];
        snprintf(buf, sizeof(buf), "domain=%s tx=%llu rx=%llu",
            stats[i].domain,
            (unsigned long long)stats[i].tx_snap,
            (unsigned long long)stats[i].rx_snap);
        env->SetObjectArrayElement(arr, i, env->NewStringUTF(buf));
    }
    return arr;
}
```

- [ ] **Step 5: Run tests**

```bash
./gradlew :netscope-sdk:connectedAndroidTest \
    --tests "*.testStatsAggregatorCumulative" \
    --tests "*.testStatsAggregatorInterval"
```

Expected: 2 PASSED

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: stats_aggregator with cumulative + interval tracking"
```

---

## Task 7: Hook Layer

**Files:**
- Modify: all `hook/*.h` and `hook/*.cpp`

- [ ] **Step 1: Implement `hook/hook_manager.h`**

```cpp
#pragma once
namespace netscope {
int  hook_manager_init();    // returns 0 on success
void hook_manager_destroy();
void hook_manager_set_paused(bool paused);
bool hook_manager_is_paused();
} // namespace netscope
```

- [ ] **Step 2: Implement `hook/hook_manager.cpp`**

```cpp
#include "hook_manager.h"
#include "hook_connect.h"
#include "hook_dns.h"
#include "hook_send_recv.h"
#include "hook_close.h"
#include "shadowhook.h"
#include <atomic>
#include <android/log.h>

#define LOG_TAG "NetScope"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace netscope {

static std::atomic<bool> g_paused{false};

int hook_manager_init() {
    int ret = shadowhook_init(SHADOWHOOK_MODE_SHARED, false);
    if (ret != 0) {
        LOGE("shadowhook_init failed: %d", ret);
        return ret;
    }
    install_hook_connect();
    install_hook_dns();
    install_hook_send_recv();
    install_hook_close();
    return 0;
}

void hook_manager_destroy() {
    uninstall_hook_connect();
    uninstall_hook_dns();
    uninstall_hook_send_recv();
    uninstall_hook_close();
}

void hook_manager_set_paused(bool paused) { g_paused.store(paused); }
bool hook_manager_is_paused()             { return g_paused.load(); }

} // namespace netscope
```

- [ ] **Step 3: Implement `hook/hook_connect.h` and `hook/hook_connect.cpp`**

`hook_connect.h`:
```cpp
#pragma once
namespace netscope {
void install_hook_connect();
void uninstall_hook_connect();
} // namespace netscope
```

`hook_connect.cpp`:
```cpp
#include "hook_connect.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../core/dns_cache.h"
#include "../utils/ip_utils.h"
#include "shadowhook.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <android/log.h>

#define LOG_TAG "NetScope"

namespace netscope {

static void* g_stub = nullptr;
static int (*orig_connect)(int, const struct sockaddr*, socklen_t) = nullptr;

static int hook_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    int ret = orig_connect(sockfd, addr, addrlen);
    if (hook_manager_is_paused() || !addr) return ret;

    char ip[64] = {};
    uint16_t port = 0;
    if (!sockaddr_to_ip(addr, ip, sizeof(ip), &port)) return ret;

    std::string domain = DnsCache::instance().lookup(ip);
    FlowTable::instance().create(sockfd, ip, port, domain.c_str());
    return ret;
}

void install_hook_connect() {
    g_stub = shadowhook_hook_sym_name(
        "libc.so", "connect",
        reinterpret_cast<void*>(hook_connect),
        reinterpret_cast<void**>(&orig_connect));
}

void uninstall_hook_connect() {
    if (g_stub) { shadowhook_unhook(g_stub); g_stub = nullptr; }
}

} // namespace netscope
```

- [ ] **Step 4: Implement `hook/hook_dns.h` and `hook/hook_dns.cpp`**

`hook_dns.h`:
```cpp
#pragma once
namespace netscope {
void install_hook_dns();
void uninstall_hook_dns();
} // namespace netscope
```

`hook_dns.cpp`:
```cpp
#include "hook_dns.h"
#include "hook_manager.h"
#include "../core/dns_cache.h"
#include "shadowhook.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

namespace netscope {

static void* g_stub = nullptr;
static int (*orig_getaddrinfo)(const char*, const char*, const struct addrinfo*, struct addrinfo**) = nullptr;

static int hook_getaddrinfo(const char* node, const char* service,
                             const struct addrinfo* hints, struct addrinfo** res) {
    int ret = orig_getaddrinfo(node, service, hints, res);
    if (hook_manager_is_paused() || ret != 0 || !node || !res || !*res) return ret;

    for (struct addrinfo* ai = *res; ai != nullptr; ai = ai->ai_next) {
        char ip[64] = {};
        if (ai->ai_family == AF_INET) {
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr, ip, sizeof(ip));
        } else if (ai->ai_family == AF_INET6) {
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr, ip, sizeof(ip));
        }
        if (ip[0] != '\0') DnsCache::instance().store(ip, node);
    }
    return ret;
}

void install_hook_dns() {
    g_stub = shadowhook_hook_sym_name(
        "libc.so", "getaddrinfo",
        reinterpret_cast<void*>(hook_getaddrinfo),
        reinterpret_cast<void**>(&orig_getaddrinfo));
}

void uninstall_hook_dns() {
    if (g_stub) { shadowhook_unhook(g_stub); g_stub = nullptr; }
}

} // namespace netscope
```

- [ ] **Step 5: Implement `hook/hook_send_recv.h` and `hook/hook_send_recv.cpp`**

`hook_send_recv.h`:
```cpp
#pragma once
namespace netscope {
void install_hook_send_recv();
void uninstall_hook_send_recv();
} // namespace netscope
```

`hook_send_recv.cpp`:
```cpp
#include "hook_send_recv.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../utils/tls_sni_parser.h"
#include "shadowhook.h"
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cstdint>

namespace netscope {

static void* g_stub_send = nullptr;
static void* g_stub_sendto = nullptr;
static void* g_stub_write = nullptr;
static void* g_stub_writev = nullptr;
static void* g_stub_recv = nullptr;
static void* g_stub_recvfrom = nullptr;
static void* g_stub_read = nullptr;
static void* g_stub_readv = nullptr;

static ssize_t (*orig_send)(int, const void*, size_t, int) = nullptr;
static ssize_t (*orig_sendto)(int, const void*, size_t, int, const struct sockaddr*, socklen_t) = nullptr;
static ssize_t (*orig_write)(int, const void*, size_t) = nullptr;
static ssize_t (*orig_writev)(int, const struct iovec*, int) = nullptr;
static ssize_t (*orig_recv)(int, void*, size_t, int) = nullptr;
static ssize_t (*orig_recvfrom)(int, void*, size_t, int, struct sockaddr*, socklen_t*) = nullptr;
static ssize_t (*orig_read)(int, void*, size_t) = nullptr;
static ssize_t (*orig_readv)(int, const struct iovec*, int) = nullptr;

static void try_resolve_domain(int fd, const void* buf, size_t len) {
    if (FlowTable::instance().is_first_send_done(fd)) return;
    FlowTable::instance().set_first_send_done(fd);

    char domain[256] = {};
    if (netscope::parse_tls_sni(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, true);
        return;
    }
    if (netscope::parse_http_host(static_cast<const uint8_t*>(buf), len, domain, sizeof(domain))) {
        FlowTable::instance().set_domain(fd, domain, false);
    }
}

static ssize_t hook_send(int fd, const void* buf, size_t len, int flags) {
    ssize_t ret = orig_send(fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_sendto(int fd, const void* buf, size_t len, int flags,
                            const struct sockaddr* dest, socklen_t dest_len) {
    ssize_t ret = orig_sendto(fd, buf, len, flags, dest, dest_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_write(int fd, const void* buf, size_t len) {
    ssize_t ret = orig_write(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) {
        try_resolve_domain(fd, buf, len);
        FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    }
    return ret;
}

static ssize_t hook_writev(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_writev(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_tx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recv(int fd, void* buf, size_t len, int flags) {
    ssize_t ret = orig_recv(fd, buf, len, flags);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_recvfrom(int fd, void* buf, size_t len, int flags,
                              struct sockaddr* src, socklen_t* src_len) {
    ssize_t ret = orig_recvfrom(fd, buf, len, flags, src, src_len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_read(int fd, void* buf, size_t len) {
    ssize_t ret = orig_read(fd, buf, len);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

static ssize_t hook_readv(int fd, const struct iovec* iov, int iovcnt) {
    ssize_t ret = orig_readv(fd, iov, iovcnt);
    if (hook_manager_is_paused() || !FlowTable::instance().contains(fd)) return ret;
    if (ret > 0) FlowTable::instance().add_rx(fd, static_cast<uint64_t>(ret));
    return ret;
}

#define HOOK(stub, lib, sym, fn, orig) \
    stub = shadowhook_hook_sym_name(lib, sym, reinterpret_cast<void*>(fn), reinterpret_cast<void**>(orig))

void install_hook_send_recv() {
    HOOK(g_stub_send,     "libc.so", "send",     hook_send,     &orig_send);
    HOOK(g_stub_sendto,   "libc.so", "sendto",   hook_sendto,   &orig_sendto);
    HOOK(g_stub_write,    "libc.so", "write",    hook_write,    &orig_write);
    HOOK(g_stub_writev,   "libc.so", "writev",   hook_writev,   &orig_writev);
    HOOK(g_stub_recv,     "libc.so", "recv",     hook_recv,     &orig_recv);
    HOOK(g_stub_recvfrom, "libc.so", "recvfrom", hook_recvfrom, &orig_recvfrom);
    HOOK(g_stub_read,     "libc.so", "read",     hook_read,     &orig_read);
    HOOK(g_stub_readv,    "libc.so", "readv",    hook_readv,    &orig_readv);
}

void uninstall_hook_send_recv() {
    shadowhook_unhook(g_stub_send);     g_stub_send = nullptr;
    shadowhook_unhook(g_stub_sendto);   g_stub_sendto = nullptr;
    shadowhook_unhook(g_stub_write);    g_stub_write = nullptr;
    shadowhook_unhook(g_stub_writev);   g_stub_writev = nullptr;
    shadowhook_unhook(g_stub_recv);     g_stub_recv = nullptr;
    shadowhook_unhook(g_stub_recvfrom); g_stub_recvfrom = nullptr;
    shadowhook_unhook(g_stub_read);     g_stub_read = nullptr;
    shadowhook_unhook(g_stub_readv);    g_stub_readv = nullptr;
}

} // namespace netscope
```

- [ ] **Step 6: Implement `hook/hook_close.h` and `hook/hook_close.cpp`**

`hook_close.h`:
```cpp
#pragma once
namespace netscope {
void install_hook_close();
void uninstall_hook_close();
} // namespace netscope
```

`hook_close.cpp`:
```cpp
#include "hook_close.h"
#include "hook_manager.h"
#include "../core/flow_table.h"
#include "../core/stats_aggregator.h"
#include "shadowhook.h"
#include <unistd.h>
#include <cstring>

namespace netscope {

static void* g_stub = nullptr;
static int (*orig_close)(int) = nullptr;

static int hook_close(int fd) {
    if (!hook_manager_is_paused() && FlowTable::instance().contains(fd)) {
        FlowEntry e{};
        if (FlowTable::instance().remove(fd, &e)) {
            const std::string domain(e.domain[0] ? e.domain : e.remote_ip);
            StatsAggregator::instance().flush(domain, e.tx_bytes, e.rx_bytes);
            StatsAggregator::instance().invokeFlowEndCallback(domain, e.tx_bytes, e.rx_bytes);
        }
    }
    return orig_close(fd);
}

void install_hook_close() {
    g_stub = shadowhook_hook_sym_name(
        "libc.so", "close",
        reinterpret_cast<void*>(hook_close),
        reinterpret_cast<void**>(&orig_close));
}

void uninstall_hook_close() {
    if (g_stub) { shadowhook_unhook(g_stub); g_stub = nullptr; }
}

} // namespace netscope
```

- [ ] **Step 7: Verify build**

```bash
./gradlew :netscope-sdk:assembleDebug
```

Expected: BUILD SUCCESSFUL

- [ ] **Step 8: Commit**

```bash
git add .
git commit -m "feat: complete hook layer (connect/dns/send_recv/close)"
```

---

## Task 8: JNI Bridge

**Files:**
- Modify: `netscope-sdk/src/main/cpp/netscope_jni.cpp` (add production JNI functions)
- Modify: `netscope-sdk/src/main/kotlin/com/netscope/sdk/NetScopeNative.kt`

- [ ] **Step 1: Finalize `NetScopeNative.kt`**

Replace file content:

```kotlin
package com.netscope.sdk

internal object NetScopeNative {
    init { System.loadLibrary("netscope") }

    external fun nativeInit(): Int        // returns 0 on success
    external fun nativeDestroy()
    external fun nativePause()
    external fun nativeResume()
    external fun nativeClearStats()
    external fun nativeMarkIntervalBoundary()
    external fun nativeGetDomainStats(): Array<DomainStats>
    external fun nativeGetIntervalStats(): Array<DomainStats>

    // Test helpers
    external fun testParseSni(buf: ByteArray): String?
    external fun testParseHttpHost(buf: ByteArray): String?
    external fun testDnsCacheStore(ip: String, domain: String)
    external fun testDnsCacheLookup(ip: String): String?
    external fun testFlowCreate(fd: Int, ip: String, port: Int, domain: String)
    external fun testFlowAddTx(fd: Int, bytes: Long)
    external fun testFlowAddRx(fd: Int, bytes: Long)
    external fun testFlowGetDomain(fd: Int): String?
    external fun testFlowGetTx(fd: Int): Long
    external fun testFlowGetRx(fd: Int): Long
    external fun testStatsClear()
    external fun testStatsFlush(domain: String, tx: Long, rx: Long)
    external fun testStatsMark()
    external fun testStatsGetCumulative(): Array<String>
    external fun testStatsGetInterval(): Array<String>
}
```

- [ ] **Step 2: Add production JNI functions to `netscope_jni.cpp`**

Add to the existing file:

```cpp
#include "hook/hook_manager.h"
#include "core/stats_aggregator.h"
using netscope::StatsAggregator;
using netscope::DomainStatsC;

// Helper: convert DomainStatsC vector to Java DomainStats[]
static jobjectArray make_stats_array(JNIEnv* env, const std::vector<DomainStatsC>& vec) {
    jclass cls = env->FindClass("com/netscope/sdk/DomainStats");
    jmethodID ctor = env->GetMethodID(cls, "<init>",
        "(Ljava/lang/String;JJJJIIJ)V");
    jobjectArray arr = env->NewObjectArray(static_cast<jsize>(vec.size()), cls, nullptr);
    for (size_t i = 0; i < vec.size(); ++i) {
        const auto& s = vec[i];
        jobject obj = env->NewObject(cls, ctor,
            env->NewStringUTF(s.domain),
            static_cast<jlong>(s.tx_total),
            static_cast<jlong>(s.rx_total),
            static_cast<jlong>(s.tx_curr + s.tx_snap),   // interval = curr for getDomain, snap for getInterval
            static_cast<jlong>(s.rx_curr + s.rx_snap),
            static_cast<jint>(s.count_total),
            static_cast<jint>(s.count_curr + s.count_snap),
            static_cast<jlong>(s.last_active_ms));
        env->SetObjectArrayElement(arr, static_cast<jsize>(i), obj);
        env->DeleteLocalRef(obj);
    }
    return arr;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeInit(JNIEnv*, jobject) {
    return netscope::hook_manager_init();
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeDestroy(JNIEnv*, jobject) {
    netscope::hook_manager_destroy();
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativePause(JNIEnv*, jobject) {
    netscope::hook_manager_set_paused(true);
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeResume(JNIEnv*, jobject) {
    netscope::hook_manager_set_paused(false);
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeClearStats(JNIEnv*, jobject) {
    StatsAggregator::instance().clear();
}
extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeMarkIntervalBoundary(JNIEnv*, jobject) {
    StatsAggregator::instance().markIntervalBoundary();
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeGetDomainStats(JNIEnv* env, jobject) {
    return make_stats_array(env, StatsAggregator::instance().getDomainStats());
}
extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeGetIntervalStats(JNIEnv* env, jobject) {
    return make_stats_array(env, StatsAggregator::instance().getIntervalStats());
}
```

- [ ] **Step 3: Verify build**

```bash
./gradlew :netscope-sdk:assembleDebug
```

Expected: BUILD SUCCESSFUL

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "feat: JNI bridge wiring production hooks to Kotlin API"
```

---

## Task 9: Kotlin API

**Files:**
- Create: `netscope-sdk/src/main/kotlin/com/netscope/sdk/DomainStats.kt`
- Create: `netscope-sdk/src/main/kotlin/com/netscope/sdk/LogcatReporter.kt`
- Create: `netscope-sdk/src/main/kotlin/com/netscope/sdk/NetScope.kt`

- [ ] **Step 1: Create `DomainStats.kt`**

```kotlin
package com.netscope.sdk

/**
 * Traffic statistics for a single domain.
 *
 * @param txBytesTotal   Cumulative bytes sent since [NetScope.init] or last [NetScope.clearStats]
 * @param rxBytesTotal   Cumulative bytes received
 * @param txBytesInterval Bytes sent in the current/last interval window
 * @param rxBytesInterval Bytes received in the current/last interval window
 * @param connCountTotal  Cumulative number of closed connections to this domain
 * @param connCountInterval Closed connections in the current/last interval window
 * @param lastActiveMs   System.currentTimeMillis() of last activity
 */
data class DomainStats(
    val domain: String,
    val txBytesTotal: Long,
    val rxBytesTotal: Long,
    val txBytesInterval: Long,
    val rxBytesInterval: Long,
    val connCountTotal: Int,
    val connCountInterval: Int,
    val lastActiveMs: Long
) {
    val totalBytes: Long get() = txBytesTotal + rxBytesTotal
}
```

- [ ] **Step 2: Create `LogcatReporter.kt`**

```kotlin
package com.netscope.sdk

import android.util.Log
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

internal object LogcatReporter {
    private const val TAG = "NetScope"
    private val scheduler = Executors.newSingleThreadScheduledExecutor { r ->
        Thread(r, "NetScope-LogcatReporter").also { it.isDaemon = true }
    }
    private var future: ScheduledFuture<*>? = null
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    fun start(intervalSeconds: Int) {
        stop()
        if (intervalSeconds <= 0) return
        future = scheduler.scheduleAtFixedRate({
            printReport()
        }, intervalSeconds.toLong(), intervalSeconds.toLong(), TimeUnit.SECONDS)
    }

    fun stop() {
        future?.cancel(false)
        future = null
    }

    private fun printReport() {
        NetScopeNative.nativeMarkIntervalBoundary()
        val interval   = NetScopeNative.nativeGetIntervalStats()
            .filter { it.txBytesInterval + it.rxBytesInterval > 0 }
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }
        val cumulative = NetScopeNative.nativeGetDomainStats()
            .sortedByDescending { it.totalBytes }

        val ts = dateFmt.format(Date())
        Log.i(TAG, "══════ Traffic Report [$ts] ══════")
        Log.i(TAG, "── Interval ──────────────────────────────")
        interval.forEach { s ->
            Log.i(TAG, "  %-40s ↑%-10s ↓%-10s conn=%d".format(
                s.domain, fmtBytes(s.txBytesInterval), fmtBytes(s.rxBytesInterval), s.connCountInterval))
        }
        Log.i(TAG, "── Cumulative ────────────────────────────")
        cumulative.forEach { s ->
            Log.i(TAG, "  %-40s ↑%-10s ↓%-10s conn=%d".format(
                s.domain, fmtBytes(s.txBytesTotal), fmtBytes(s.rxBytesTotal), s.connCountTotal))
        }
        Log.i(TAG, "═════════════════════════════════════════")
    }

    private fun fmtBytes(bytes: Long): String = when {
        bytes >= 1_048_576 -> "%.1f MB".format(bytes / 1_048_576.0)
        bytes >= 1_024     -> "%.1f KB".format(bytes / 1_024.0)
        else               -> "$bytes B"
    }
}
```

- [ ] **Step 3: Create `NetScope.kt`**

```kotlin
package com.netscope.sdk

import android.content.Context
import android.util.Log

/**
 * Entry point for NetScope network traffic monitoring SDK.
 *
 * Call [init] once in your Application.onCreate(). The SDK installs PLT hooks into
 * the current process and begins tracking all TCP connections and their byte counts,
 * attributing traffic to domain names via TLS SNI, HTTP Host header, and DNS cache.
 */
object NetScope {

    private const val TAG = "NetScope"
    private var initialized = false
    private var flowEndCallback: ((DomainStats) -> Unit)? = null

    /**
     * Load native library, install PLT hooks, start collecting statistics.
     * Safe to call multiple times — subsequent calls are no-ops.
     */
    @Synchronized
    fun init(context: Context) {
        if (initialized) return
        val ret = NetScopeNative.nativeInit()
        if (ret != 0) {
            Log.e(TAG, "Native init failed: $ret")
            return
        }
        initialized = true
        Log.i(TAG, "Initialized")
    }

    /** Pause stats collection. PLT hooks remain installed; bytes are not counted. */
    fun pause() = NetScopeNative.nativePause()

    /** Resume stats collection after [pause]. */
    fun resume() = NetScopeNative.nativeResume()

    /**
     * Uninstall all PLT hooks and release native resources.
     * Typically not needed — only call when you want to completely remove the SDK.
     */
    fun destroy() {
        NetScopeNative.nativeDestroy()
        LogcatReporter.stop()
        initialized = false
    }

    /** Reset all collected statistics. Hooks are unaffected. */
    fun clearStats() = NetScopeNative.nativeClearStats()

    /**
     * Mark the end of the current interval window.
     * After this call, [getIntervalStats] returns the just-completed window's data,
     * and a new window begins. Called automatically by [setLogInterval].
     */
    fun markIntervalBoundary() = NetScopeNative.nativeMarkIntervalBoundary()

    /**
     * Return cumulative domain statistics since [init] or last [clearStats],
     * sorted by total traffic descending.
     */
    fun getDomainStats(): List<DomainStats> =
        NetScopeNative.nativeGetDomainStats().sortedByDescending { it.totalBytes }

    /**
     * Return statistics for the last **completed** interval window (since last [markIntervalBoundary]),
     * sorted by interval traffic descending.
     */
    fun getIntervalStats(): List<DomainStats> =
        NetScopeNative.nativeGetIntervalStats()
            .sortedByDescending { it.txBytesInterval + it.rxBytesInterval }

    /**
     * Enable automatic Logcat output every [seconds] seconds (Tag: NetScope).
     * Each print also calls [markIntervalBoundary].
     * Pass 0 to disable.
     */
    fun setLogInterval(seconds: Int) {
        if (seconds > 0) LogcatReporter.start(seconds) else LogcatReporter.stop()
    }

    /**
     * Register a callback invoked on the reporting thread each time a connection closes.
     * The [DomainStats] parameter reflects the delta for that single connection (txBytesInterval/rxBytesInterval).
     * Keep the callback lightweight.
     */
    fun setOnFlowEnd(callback: (DomainStats) -> Unit) {
        flowEndCallback = callback
        // Route native callback through JNI → this lambda
        // (wired in Task 8 via StatsAggregator::setFlowEndCallback)
    }
}
```

- [ ] **Step 4: Wire `setOnFlowEnd` callback through JNI**

Add to `netscope_jni.cpp`:

```cpp
// Global reference to callback lambda (set via setFlowEndCallback JNI)
static JavaVM* g_jvm = nullptr;
static jobject g_callback_obj = nullptr;  // GlobalRef to Kotlin lambda (Function1)

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
Java_com_netscope_sdk_NetScopeNative_nativeSetFlowEndCallback(JNIEnv* env, jobject,
                                                               jobject callback) {
    if (g_callback_obj) { env->DeleteGlobalRef(g_callback_obj); g_callback_obj = nullptr; }
    if (!callback) {
        StatsAggregator::instance().setFlowEndCallback(nullptr);
        return;
    }
    g_callback_obj = env->NewGlobalRef(callback);
    StatsAggregator::instance().setFlowEndCallback([](const netscope::DomainStatsC& s) {
        JNIEnv* env2 = nullptr;
        if (!g_jvm || g_jvm->AttachCurrentThread(&env2, nullptr) != JNI_OK) return;
        jclass cls = env2->FindClass("com/netscope/sdk/DomainStats");
        jmethodID ctor = env2->GetMethodID(cls, "<init>", "(Ljava/lang/String;JJJJIIJ)V");
        jobject obj = env2->NewObject(cls, ctor,
            env2->NewStringUTF(s.domain),
            0LL, 0LL,
            static_cast<jlong>(s.tx_curr),
            static_cast<jlong>(s.rx_curr),
            0, 1,
            static_cast<jlong>(s.last_active_ms));
        jclass fn_cls = env2->GetObjectClass(g_callback_obj);
        jmethodID invoke = env2->GetMethodID(fn_cls, "invoke", "(Ljava/lang/Object;)Ljava/lang/Object;");
        env2->CallObjectMethod(g_callback_obj, invoke, obj);
        env2->DeleteLocalRef(obj);
        g_jvm->DetachCurrentThread();
    });
}
```

Add to `NetScopeNative.kt`:
```kotlin
external fun nativeSetFlowEndCallback(callback: ((DomainStats) -> Unit)?)
```

Update `NetScope.setOnFlowEnd`:
```kotlin
fun setOnFlowEnd(callback: (DomainStats) -> Unit) {
    flowEndCallback = callback
    NetScopeNative.nativeSetFlowEndCallback(callback)
}
```

- [ ] **Step 5: Build and verify**

```bash
./gradlew :netscope-sdk:assembleDebug
```

Expected: BUILD SUCCESSFUL

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: Kotlin API (NetScope/DomainStats/LogcatReporter) with JNI wiring"
```

---

## Task 10: Integration Test

**Files:**
- Modify: `NetScopeInstrumentedTest.kt` (add end-to-end test)
- Create: `app/src/main/kotlin/com/netscope/app/SampleApplication.kt`
- Create: `app/src/main/kotlin/com/netscope/app/MainActivity.kt`

- [ ] **Step 1: Write failing integration test**

Add to `NetScopeInstrumentedTest.kt`:

```kotlin
@Test
fun testEndToEndHttpsTrafficCaptured() {
    // Must run with INTERNET permission on a device with connectivity
    NetScope.init(androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext)
    NetScope.clearStats()

    val client = okhttp3.OkHttpClient()
    val request = okhttp3.Request.Builder()
        .url("https://httpbin.org/get")
        .build()
    client.newCall(request).execute().use { response ->
        assertTrue("HTTP call should succeed", response.isSuccessful)
    }

    // Give close() hook time to flush
    Thread.sleep(300)

    val stats = NetScope.getDomainStats()
    val httpbin = stats.firstOrNull { it.domain.contains("httpbin.org") }
    assertNotNull("httpbin.org should appear in stats", httpbin)
    assertTrue("Should have sent some bytes", httpbin!!.txBytesTotal > 0)
    assertTrue("Should have received some bytes", httpbin.rxBytesTotal > 0)
}
```

- [ ] **Step 2: Run test**

```bash
./gradlew :netscope-sdk:connectedAndroidTest --tests "*.testEndToEndHttpsTrafficCaptured"
```

Expected: PASSED (domain `httpbin.org` appears with non-zero TX/RX)

- [ ] **Step 3: Create `SampleApplication.kt`**

```kotlin
package com.netscope.app

import android.app.Application
import android.util.Log
import com.netscope.sdk.NetScope

class SampleApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)
        NetScope.setLogInterval(30)
        NetScope.setOnFlowEnd { stats ->
            Log.d("NetScope-App", "Flow ended: ${stats.domain} ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
        }
    }
}
```

- [ ] **Step 4: Create `MainActivity.kt`**

```kotlin
package com.netscope.app

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.netscope.sdk.NetScope
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.Request

class MainActivity : AppCompatActivity() {
    private val scope = MainScope()
    private val client = OkHttpClient()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        findViewById<Button>(R.id.btnFetch).setOnClickListener {
            scope.launch(Dispatchers.IO) {
                listOf(
                    "https://httpbin.org/get",
                    "https://www.google.com",
                    "https://api.github.com"
                ).forEach { url ->
                    runCatching {
                        client.newCall(Request.Builder().url(url).build()).execute().close()
                    }
                }
                withContext(Dispatchers.Main) { refreshStats() }
            }
        }

        findViewById<Button>(R.id.btnClear).setOnClickListener {
            NetScope.clearStats()
            refreshStats()
        }

        refreshStats()
    }

    private fun refreshStats() {
        val sb = StringBuilder()
        NetScope.getDomainStats().forEach { s ->
            sb.appendLine("${s.domain}")
            sb.appendLine("  ↑${fmtBytes(s.txBytesTotal)}  ↓${fmtBytes(s.rxBytesTotal)}  conn=${s.connCountTotal}")
        }
        findViewById<TextView>(R.id.tvStats).text = sb.toString().ifEmpty { "No traffic yet" }
    }

    private fun fmtBytes(b: Long) = when {
        b >= 1_048_576 -> "%.1f MB".format(b / 1_048_576.0)
        b >= 1_024     -> "%.1f KB".format(b / 1_024.0)
        else           -> "$b B"
    }

    override fun onDestroy() { super.onDestroy(); scope.cancel() }
}
```

- [ ] **Step 5: Create `app/src/main/res/layout/activity_main.xml`**

```xml
<?xml version="1.0" encoding="utf-8"?>
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:orientation="vertical"
    android:padding="16dp">

    <Button android:id="@+id/btnFetch"
        android:layout_width="wrap_content" android:layout_height="wrap_content"
        android:text="Fetch URLs" />

    <Button android:id="@+id/btnClear"
        android:layout_width="wrap_content" android:layout_height="wrap_content"
        android:text="Clear Stats" android:layout_marginTop="8dp"/>

    <ScrollView android:layout_width="match_parent" android:layout_height="0dp"
        android:layout_weight="1" android:layout_marginTop="16dp">
        <TextView android:id="@+id/tvStats"
            android:layout_width="match_parent" android:layout_height="wrap_content"
            android:fontFamily="monospace" android:textSize="12sp"/>
    </ScrollView>
</LinearLayout>
```

- [ ] **Step 6: Commit**

```bash
git add .
git commit -m "feat: integration test + sample app demonstrating full SDK usage"
```

---

## Task 11: AAR Packaging

**Files:**
- Modify: `netscope-sdk/build.gradle` (Maven publish already present)

- [ ] **Step 1: Build release AAR**

```bash
./gradlew :netscope-sdk:assembleRelease
```

Expected: `netscope-sdk/build/outputs/aar/netscope-sdk-release.aar`

- [ ] **Step 2: Verify .so files are inside the AAR**

```bash
unzip -l netscope-sdk/build/outputs/aar/netscope-sdk-release.aar | grep ".so"
```

Expected output includes:
```
  jni/arm64-v8a/libnetscope.so
  jni/arm64-v8a/libshadowhook.so
  jni/armeabi-v7a/libnetscope.so
  jni/armeabi-v7a/libshadowhook.so
```

- [ ] **Step 3: Publish to local Maven repo**

```bash
./gradlew :netscope-sdk:publishReleasePublicationToLocalRepoRepository
```

Expected: artifact at `build/repo/com/netscope/netscope-sdk/1.0.0/`

- [ ] **Step 4: Verify local Maven integration in the sample app**

Temporarily add to `settings.gradle`:
```groovy
maven { url = uri("${rootProject.buildDir}/repo") }
```

Then change `app/build.gradle` to use the published artifact:
```groovy
implementation 'com.netscope:netscope-sdk:1.0.0'
```

```bash
./gradlew :app:assembleDebug
```

Expected: BUILD SUCCESSFUL using AAR from local Maven repo.

Revert to `implementation project(':netscope-sdk')` after verifying.

- [ ] **Step 5: Commit**

```bash
git add .
git commit -m "build: verify AAR contains arm64 + armeabi-v7a .so, local Maven publish works"
```

---

## Self-Review

**Spec coverage check:**

| Spec Requirement | Covered in Task |
|-----------------|----------------|
| PLT Hook libc (connect/send/recv/close/getaddrinfo) | Task 7 |
| Java layer + C++ layer coverage | Task 7 (all .so via PLT hook) |
| TLS SNI extraction | Task 3 + Task 7 (hook_send_recv) |
| HTTP Host fallback | Task 3 + Task 7 |
| DNS cache IP→domain | Task 4 + Task 7 (hook_dns) |
| FlowEntry per-fd tracking | Task 5 |
| Per-domain cumulative stats | Task 6 |
| Per-domain interval stats (mark/snapshot) | Task 6 |
| Java API: init/pause/resume/destroy/clearStats | Task 9 |
| Java API: getDomainStats/getIntervalStats | Task 9 |
| Java API: setLogInterval (periodic Logcat) | Task 9 |
| Java API: setOnFlowEnd callback | Task 9 |
| Logcat: interval + cumulative dual output | Task 9 (LogcatReporter) |
| AAR packaging (Maven + local file) | Task 11 |
| Android 10+ (API 29), arm64-v8a + armeabi-v7a | Task 1 |

**Type consistency check:** `DomainStats` constructor used in `make_stats_array` (Task 8) matches the data class defined in Task 9 — both have 8 parameters `(String, Long, Long, Long, Long, Int, Int, Long)`. ✓

**Placeholder scan:** No TBD/TODO in code steps. ✓
