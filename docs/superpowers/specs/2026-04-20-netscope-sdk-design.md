# NetScope SDK 设计文档

**日期：** 2026-04-20
**目标平台：** Android 10+（API 29），车机 / 平板
**交付形式：** AAR 依赖库

---

## 1. 背景与目标

车机及平板上的 Android 应用需要按域名统计自身 HTTP/HTTPS 网络流量（上行 + 下行），覆盖 Java 层和 C++ / NDK 层的所有网络调用。

**为什么不用 VpnService（PCAPdroid 方案）：** AAOS 和定制车机 ROM 普遍禁用 VpnService 或屏蔽弹窗，无法建立本地 VPN 隧道。

**核心思路：** 以 PLT Hook 拦截目标 App 进程内所有 `.so` 的 libc 网络函数，在 syscall 层统一采集，不依赖任何系统权限或 VPN。

---

## 2. 依赖

| 组件 | 版本 | 用途 |
|------|------|------|
| shadowhook（字节跳动） | 1.0.9+ | PLT/Inline Hook 框架，线程安全，Android 5.0+ |
| Android NDK | r25c+ | C++ 核心层编译 |
| Kotlin | 1.9+ | Java 公共 API 层 |

ABI 支持：`arm64-v8a`（主力），`armeabi-v7a`（可选兼容）

---

## 3. 整体架构

```
NetScope SDK (AAR)
│
├── Java/Kotlin 公共 API 层
│   └── NetScope.kt          ← 单例入口，init/pause/resume/destroy/query
│   └── DomainStats.kt       ← 数据模型
│   └── NetScopeNative.kt    ← JNI 声明
│
├── JNI 桥接
│   └── netscope_jni.cpp     ← Java ↔ C++ 数据转换
│
└── Native C++ 核心层
    ├── hook/
    │   ├── hook_manager.cpp     ← shadowhook 初始化，注册/卸载所有 Hook
    │   ├── hook_connect.cpp     ← Hook connect()
    │   ├── hook_send_recv.cpp   ← Hook send/sendto/write/writev/recv/recvfrom/read/readv
    │   ├── hook_dns.cpp         ← Hook getaddrinfo()
    │   └── hook_close.cpp       ← Hook close()
    │
    ├── core/
    │   ├── flow_table.cpp       ← fd → FlowEntry 连接表（读写锁）
    │   ├── dns_cache.cpp        ← IP → 域名映射缓存（带 TTL，默认 60s）
    │   └── stats_aggregator.cpp ← 按域名聚合累计 & 增量统计
    │
    └── utils/
        ├── tls_sni_parser.cpp   ← TLS ClientHello SNI 字段解析
        └── ip_utils.cpp         ← IPv4/IPv6 地址字符串工具
```

---

## 4. Hook 函数清单

| 函数 | 库 | 拦截目的 |
|------|----|---------|
| `connect` | libc.so | 记录 fd → {IP, port}，查 DNS 缓存关联域名 |
| `getaddrinfo` | libc.so | DNS 解析完成时写入 IP → 域名映射 |
| `send` | libc.so | 统计上行字节；首包检测 TLS ClientHello / HTTP Host |
| `sendto` | libc.so | 统计上行字节（UDP / sendto 形式） |
| `write` | libc.so | 兼容直接写 socket 的场景 |
| `writev` | libc.so | 兼容 scatter-gather 写 |
| `recv` | libc.so | 统计下行字节 |
| `recvfrom` | libc.so | 统计下行字节（含 UDP） |
| `read` | libc.so | 兼容直接读 socket 的场景 |
| `readv` | libc.so | 兼容 scatter-gather 读 |
| `close` | libc.so | 刷入统计，清理 flow_table 条目 |

---

## 5. 域名解析策略

每条连接的域名按以下优先级确定：

```
1. TLS SNI（最高）
   send() 首包 → 检测 TLS ClientHello（Byte[0]==0x16, Byte[5]==0x01）
   → 解析 extension_type==0x0000 的 SNI 字段 → 写入 FlowEntry.domain

2. HTTP Host 头
   send() 首包非 TLS → 检测 "Host:" 字段 → 写入 FlowEntry.domain

3. DNS 缓存（次之）
   connect() 时 → 以 remote_ip 查 dns_cache → 命中则写入 FlowEntry.domain

4. IP 地址字符串（兜底）
   以上均失败时，domain = remote_ip 字符串
```

---

## 6. 核心数据结构

```cpp
// 活跃连接（flow_table，fd 为 key）
struct FlowEntry {
    int      fd;
    char     remote_ip[64];
    uint16_t remote_port;
    char     domain[256];
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    bool     domain_resolved;   // 是否已通过 SNI/Host 确定域名
    bool     first_send_done;   // 首包是否已检测
};

// 聚合统计（stats_aggregator，domain 为 key）
struct DomainStats {
    char     domain[256];
    uint64_t tx_bytes_total;     // 累计上行
    uint64_t rx_bytes_total;     // 累计下行
    uint64_t tx_bytes_interval;  // 当前窗口增量上行
    uint64_t rx_bytes_interval;  // 当前窗口增量下行
    uint32_t conn_count_total;
    uint32_t conn_count_interval;
    int64_t  last_active_ms;
};
```

---

## 7. 线程安全

| 数据结构 | 并发策略 |
|---------|---------|
| flow_table | `std::shared_mutex`（读写锁），读多写少 |
| dns_cache | `std::shared_mutex` + TTL 过期惰性清理 |
| stats_aggregator | `std::atomic<uint64_t>` 字段级原子操作，避免全局锁 |

---

## 8. Java 公共 API

```kotlin
object NetScope {
    /**
     * 加载 Native 库，安装所有 PLT Hook，开始统计。
     * 在 Application.onCreate() 中调用一次。
     */
    fun init(context: Context)

    /** 暂停统计写入（Hook 保留，数据不再更新） */
    fun pause()

    /** 恢复统计写入 */
    fun resume()

    /** 卸载所有 Hook，释放 Native 资源（通常无需调用） */
    fun destroy()

    /** 重置所有统计数字（Hook 不受影响） */
    fun clearStats()

    /** 标记当前增量窗口结束，开始新窗口（不影响累计） */
    fun markIntervalBoundary()

    /** 获取累计统计（从 init 或上次 clearStats 至今），按总流量降序 */
    fun getDomainStats(): List<DomainStats>

    /** 获取上一个增量窗口内的统计 */
    fun getIntervalStats(): List<DomainStats>

    /**
     * 设置 Logcat 自动打印间隔（秒）。
     * 每次打印时自动调用 markIntervalBoundary()。
     * 传 0 关闭自动打印。默认 30s。
     */
    fun setLogInterval(seconds: Int)

    /** 每条连接关闭时触发，参数为该连接的域名流量快照 */
    fun setOnFlowEnd(callback: (DomainStats) -> Unit)
}

data class DomainStats(
    val domain: String,
    val txBytesTotal: Long,
    val rxBytesTotal: Long,
    val txBytesInterval: Long,
    val rxBytesInterval: Long,
    val connCountTotal: Int,
    val connCountInterval: Int,
    val lastActiveMs: Long
)
```

---

## 9. Logcat 输出格式

Tag: `NetScope`

```
[NetScope] ══════ Traffic Report [2026-04-20 10:30:00] ══════
[NetScope] ── Interval (last 30s) ──────────────────────────
[NetScope]  api.example.com        ↑12.3 KB  ↓1.2 MB   conn=5
[NetScope]  cdn.example.com        ↑512 B    ↓58.7 MB  conn=1
[NetScope] ── Cumulative (since start) ──────────────────────
[NetScope]  api.example.com        ↑128.3 KB ↓12.5 MB  conn=45
[NetScope]  cdn.example.com        ↑4.1 KB   ↓238.2 MB conn=12
[NetScope] ═════════════════════════════════════════════════
```

---

## 10. 使用方法

### 集成（build.gradle）

```groovy
dependencies {
    implementation 'com.netscope:netscope-sdk:1.0.0'
}
```

### 初始化

```kotlin
class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        NetScope.init(this)
        NetScope.setLogInterval(30) // 每 30s 打印一次
    }
}
```

### 查询统计

```kotlin
// 获取全量累计
val stats = NetScope.getDomainStats()
stats.forEach { s ->
    Log.d("App", "${s.domain}: ↑${s.txBytesTotal} ↓${s.rxBytesTotal}")
}

// 获取最近一个窗口增量
val intervalStats = NetScope.getIntervalStats()
```

### 实时回调

```kotlin
NetScope.setOnFlowEnd { stats ->
    // 每条连接关闭时触发
    Log.d("App", "Connection to ${stats.domain} closed: ↑${stats.txBytesInterval} ↓${stats.rxBytesInterval}")
}
```

---

## 11. 已知边界条件

| 情况 | 处理方式 |
|------|---------|
| `getaddrinfo` 在 `connect` 之后才返回（极少） | `connect` 先暂存 IP，`getaddrinfo` 回调时补填域名 |
| 静态链接 libc 的 `.so`（极少见） | PLT Hook 失效，该 `.so` 的流量只能统计字节，域名显示为 IP |
| HTTP/2 多路复用（多 stream 共享一个 fd） | 字节数正确统计，域名通过 SNI 确定（HTTP/2 基本都走 TLS） |
| IPv6 地址 | `dns_cache` 和 `flow_table` 均用字符串 key，兼容 IPv6 |
| TLS 1.3 早期数据（0-RTT） | SNI 在第一个 ClientHello 中，解析逻辑不变 |

---

## 12. 验证方法

1. **覆盖率测试**：分别用 OkHttp、HttpURLConnection、NDK socket、curl（C++）发起请求，确认四种场景均有统计
2. **域名准确性**：对比 Wireshark/Charles 抓包结果与 SDK 统计的域名列表
3. **车机兼容性**：在 AAOS 模拟器（禁用 VPN）上运行，确认 SDK 正常工作
4. **Release 构建**：关闭 debug 模式后验证 Hook 仍然生效
5. **性能基准**：视频流场景下测量 CPU 增量（目标 < 1%）和内存占用（目标 < 5MB）
