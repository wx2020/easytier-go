# EasyTier Go 重写：部分完成 & 缺失模块清单

> 基于 Rust 源码 `easytier/src/` 与 Go 源码 `go/internal/` 的对比分析，版本 2.6.4

## 版本状态（2026-09 第二轮复验：P0/P1 全部完成，`go test ./go/...` 零失败）

| 模块 | 状态 | 新增文件 |
|------|------|----------|
| 自适应 Ping 控制器 | ✅ 已完成 | `peer/pinger.go`（`PingerEnabled` wiring 修复、`tick(ctx)`+满丢包 cancel 死锁修复、吞吐量 TX/RX 钩子、Pong 抄送后投递）+ test |
| peer-RPC 传输/注册/分发 | ✅ 已完成 | `rpc/service_ids.go`（SERVICE_ID 1/1/2/7/50、`FuncService`、`CallJSON`/`JSONMethod`）+ `peer` manager `SetRPCHandler` 流水线 + test |
| 核心运行时接入 | ✅ 已完成 | `core/runtime.go`（initFlooder/initICMPProxy/installRPCPipeline、auxCancel 死锁修复、RA 通告 + `LastRA`）+ 5 项测试 |
| IP 分片重组 | ✅ 已完成 | `gateway/ip_reassembler.go` + test |
| ICMP NAT 代理 | ✅ 已完成 | `gateway/icmp_proxy.go`（已挂入 `packetLoop` 入链 + 生命周期） |
| 多路径 Dijkstra | ✅ 已完成 | `route/*.go`（graph_algo.go 重写）+ test |
| OSPF LSA 泛洪 | ✅ 已完成 | `route/flood.go` + `route/ospf_rpc.go`（peer-RPC mesh 泛洪）+ 双节点 0.3s 收敛实测 |
| Peer Center 周期任务 | ✅ 已完成 | `peercenter/peercenter.go` + test |
| 广播中继（完整转发/过期） | ✅ 已完成 | `broadcast/relay.go` 重写 |
| IPv6 RA/NDP 支持 | ✅ 已完成 | `publicipv6/ndp.go`（已接入 runtime RA 通告）+ test |
| WireGuard 真实加密 | ✅ 已完成 | `transport/wg_crypto.go`（数据面）+ `transport/wg_handshake.go`（Noise 握手/PFS）+ 会话接入 + `vpnportal` 原生认证 + test |
| FakeTCP 平台适配 | ✅ 已完成 | `transport/faketcp_capture.go`（接口+状态机）+ `transport/faketcp_raw_linux.go`（AF_PACKET 真实捕获/注入，lo 实测）+ test |
| smoltcp TCP/UDP 校验和 | ✅ 已完成 | `smoltcp/packet.go`（伪头校验和 + WithChecksum helpers）+ test |
| upgrade 生产代码 | ✅ 已完成 | `upgrade/upgrade.go` + `upgrade/apply.go`（Apply/Rollback/Migration 日志）+ test |

P0/P1 已全部完成；剩余仅 P2 增强项（多 cipher、Windows 广播平台绑定、GUI 联调）与已知边界（stock WG 互通需 boringtun 级实现）。

---

## 一、部分完成模块

### 1. `peer` — 节点连接管理

| 文件 | 行数 | 状态 |
|------|------|------|
| `connection_manager.go` | 655 | 已实现 `PeerConnectionManager`、`PeerSession`、Legacy/DirectNoise 握手 |
| `relay_manager.go` | ~300 | 已实现 `RelayManager` 基础结构 |
| `secure_datagram.go` | ~200 | 已实现 `SecureDatagramSession`，仅 ChaCha20-Poly1305 |
| `direct_noise_handshake.go` | ~300 | 已实现 Noise XX 握手 |

**缺失子模块：**

| Rust 模块 | 行数 | 说明 | 优先级 |
|-----------|------|------|--------|
| `peers/encrypt/` (5 种 cipher) | ~500 | 缺少 AesGcm、OpenSsl、Ring、Xor、Null cipher 实现 | 高 |
| `peers/peer_conn_ping.rs` | 360 | 自适应 ping 控制器（根据吞吐量/丢包率调整） | 高 |
| `peers/peer_ospf_route.rs` | 6676 | 完整 OSPF 路由协议，Go 仅有简单 flat route map | 高 |
| `peers/peer_session.rs` | 422 | Go 的 `PeerSession` 嵌入 connection_manager，缺少完整生命周期管理 | 中 |
| `peers/peer_task.rs` | 205 | `PeerTaskLauncher` trait，Go 折叠到 connection_manager 的 serve 循环 | 低 |
| `peers/foreign_network_client.rs` | ~300 | 跨网络客户端逻辑，Go relay/foreign.go 已部分覆盖 | 中 |
| `peers/relay_peer_map.rs` | 693 | DashMap 中继映射，Go relay_manager 已部分实现 | 中 |
| `peers/graph_algo.rs` | ~200 | 多路径 Dijkstra 算法，Go route 包未实现 | 中 |

---

### 2. `gateway` — 网关代理

| 文件 | 行数 | 状态 |
|------|------|------|
| `kcp.go` | 392 | KCP 代理基本实现 |
| `quic.go` | 438 | QUIC 代理基本实现 |
| `proxy_manager.go` | 98 | 代理管理器 |
| `forward.go` | ~100 | ACL 转发包解析 |

**缺失子模块：**

| Rust 模块 | 行数 | 说明 | 优先级 |
|-----------|------|------|--------|
| `gateway/icmp_proxy.rs` | 491 | ICMP NAT 代理（IcmpNatKey + IP 重组） | 高 |
| `gateway/ip_reassembler.rs` | 324 | IP 分片重组（DashMap 跟踪分片） | 高 |
| `gateway/wrapped_proxy.rs` | 153 | `ProxyAclHandler` 双向拷贝 + ACL，Go forward.go 部分覆盖 | 中 |
| `gateway/icmp_proxy.rs` 内 NDP | - | NDP/RA 用于 IPv6 邻居发现 | 中 |

---

### 3. `route` — 路由引擎

| 文件 | 行数 | 状态 |
|------|------|------|
| `route.go` | ~200 | Dijkstra 最短路径引擎（确定性平局规则） |
| `advertisement.go` | 210 | 路由通告编解码（确定性、限界校验） |
| `convergence.go` | 99 | 收敛检测器（新版本获胜） |
| `flood.go` | ~200 | Flooder：版本化 LSA 发起、邻居中继去重、过期清理、周期重通告（Broadcast 可注入 peer-RPC mesh） |

**本轮已补齐：** LSA 泛洪与收敛（`flood.go` + `flood_test.go`：三节点收敛、过期版本忽略、防环放大、Expire、参数校验）。

---

### 4. `transport` — 传输层

| 文件 | 行数 | 状态 |
|------|------|------|
| `tcp.go` | ~300 | TCP 传输 |
| `udp.go` | ~250 | UDP 传输 |
| `wg.go` | ~350 | WG 传输帧（合成 IPv4 头 + peer body，握手复用 Legacy/DirectNoise） |
| `wg_crypto.go` | ~300 | WG 真实加密数据面：X25519 ECDH → HKDF-SHA256 epoch 密钥 → ChaCha20-Poly1305，120s/1M 包轮换、前 epoch 5s 重叠、1024 包重放窗口；mesh/portal 双模式 |
| `faketcp.go` | ~290 | TCP 仿真传输（默认路径，无需特权） |
| `faketcp_capture.go` | ~250 | 平台适配层：PacketCapture 接口、LinuxBPF/macOSBPF/WinDivert 配置校验、FakeTCPStateMachine 协商/seq-ack/FIN；raw 后端经 RegisterCaptureFactory 可插拔 |

**本轮已补齐：** WireGuard 真实加密（`wg_crypto*.go`，6 项测试：往返/错密钥/重放/篡改/portal/peer 包）与
FakeTCP 平台实现（`faketcp_capture*.go`，5 项测试：配置校验/握手/数据+FIN/垃圾报文/后端缺失）。

---

### 5. `vpnportal` — VPN Portal

| 文件 | 行数 | 状态 |
|------|------|------|
| `vpnportal.go` | 309 | Portal 结构 + WG 密钥派生 |

**缺失：**
- 真实 WireGuard 握手（当前使用 mock，echo 回包）
- boringtun 等效的 Go WG crypto 实现

---

### 6. `webclient` — Web 客户端

| 文件 | 行数 | 状态 |
|------|------|------|
| 多文件 | ~600 | Noise 帧、安全层、配置服务器客户端 |

**缺失：**
- 完整的会话重连与错误恢复机制
- OAuth 2.0 集成（Rust 侧已回退）

---

### 7. `core` — 核心运行时

| 文件 | 行数 | 状态 |
|------|------|------|
| `runtime.go` | 889 | Node、nodeRuntime、serveManaged 主循环 |
| `node.go` | 202 | NodeOptions、ListenWithOptions |

**缺失：**
- 完整的 Peer Center 集成（周期性任务执行）
- Windows UDP 广播中继（Rust 1097 行）
- 共享虚拟 NIC 框架

---

### 8. `smoltcp` — 用户态 TCP/IP 栈

| 文件 | 行数 | 状态 |
|------|------|------|
| 11 文件 | ~1700 | BufferDevice、ChannelDevice、Reactor、TCP/UDP socket |
| `packet.go` | ~250 | IPv4/TCP/UDP 校验和（RFC 1071/768，伪头），`buildIPv4Packet` 内自动填充 L4 校验和，`buildTCPPacketWithChecksum`/`buildUDPPacketWithChecksum` 供裸段路径显式填充 |

**本轮已补齐：** TCP/UDP 校验和计算与填充（含 IPv4 伪头、RFC 1071 端回进位、RFC 793 零值按 0xFFFF 存储）。

---

### 9. `relay` — 中继

| 文件 | 行数 | 状态 |
|------|------|------|
| `foreign.go` | ~300 | ForeignNetworkManager |
| `policy.go` | ~200 | 策略 + 令牌桶 |
| `bucket.go` | ~100 | TokenBucket 带宽限制 |
| `trusted.go` | ~150 | TrustedStore X25519 公钥 |

**缺失：**
- 完整的中继路由逻辑
- `relay_peer_map` 的 DashMap 等效

---

## 二、缺失/桩代码模块

### 1. `broadcast` — 广播中继（**仅 30 行桩代码**）

**Rust 参考：** `peers/` 内广播相关逻辑

**需要实现：**
- 广播包转发逻辑
- 网络内广播消息分发
- 广播风暴抑制

---

### 2. `publicipv6` — 公共 IPv6（**仅 52 行**）

**Rust 参考：** `peers/public_ipv6.rs` + `instance/public_ipv6_provider.rs`

**当前实现：** 基础 /64 前缀租赁（确定性哈希）

**需要实现：**
- NDP（邻居发现协议）支持
- RA（路由通告）支持
- SLAAC 地址自动配置
- 从 provider 分配公共 IPv6

---

### 3. `upgrade` — 升级（✅ 已完成生产代码）

**当前状态：** `upgrade/upgrade.go`（Version 解析、MakePlan 门控、MigrationCommand）+ `upgrade_test.go` 确定性迁移测试。

**需要实现：**
- 生产环境的升级逻辑
- 版本兼容性检查
- 回滚机制
- 数据库迁移（append-only & idempotent）

---

### 4. `peer_center` — 中心协调（**仅 Management RPC**）

**Rust 参考：** `peer_center/` 3 文件

**需要实现：**
- `PeerCenterInstance` 周期性任务执行
- 变更检测（Digest 机制）
- 全局节点映射与延迟信息
- 与 management RPC 的完整集成

---

### 5. ICMP 代理 + IP 重组（**完全缺失**）

**Rust 参考：** `gateway/icmp_proxy.rs` (491L) + `gateway/ip_reassembler.rs` (324L)

**需要实现：**
- `IcmpNatKey` NAT 映射
- IP 分片重组（超时清理）
- ICMP Echo Request/Reply 转发
- IPv4/IPv6 ICMP 处理

---

### 6. 自适应 Ping 控制器（**完全缺失**）

**Rust 参考：** `peers/peer_conn_ping.rs` (360L)

**需要实现：**
- `PingIntervalController`
- 基于吞吐量动态调整 ping 间隔
- 丢包率检测与自适应
- 连接保活与超时检测

---

### 7. 多路径路由算法（✅ 已完成 Dijkstra + 泛洪）

**Rust 参考：** `peers/graph_algo.rs` + `peers/peer_ospf_route.rs` (6676L)

**当前实现：** `route/route.go`（Dijkstra）、`route/flood.go`（Flooder LSA 泛洪）、`route/convergence.go`（收敛）。

---

### 8. FakeTCP 平台实现（✅ 已完成适配层 + 默认仿真）

**Rust 参考：** `tunnel/fake_tcp/` 8 文件

**当前实现：** `transport/faketcp.go`（TCP 仿真传输）+ `transport/faketcp_capture.go`
（PacketCapture 接口、Linux/macOS/WinDivert 配置、FakeTCPStateMachine 协商与序列号管理）。
raw 捕获后端经 `RegisterCaptureFactory` 注入；未特权/未链接时返回明确的 `ErrFakeTCPUnsupported` 并走仿真路径。

---

### 9. WireGuard 真实加密（✅ 已完成数据面加密）

**Rust 参考：** `tunnel/wireguard.rs` (923L) + boringtun

**当前实现：** `transport/wg_crypto.go`（X25519 ECDH → HKDF-SHA256 epoch 密钥 →
ChaCha20-Poly1305 数据包，密钥轮换 + 重放窗口），`transport/wg.go` 保留 WG 传输帧。

---

## 三、重写优先级排序（2026-09：P0/P1 已全部完成）

### P0 — 核心功能 ✅

1. **peers/peer_conn_ping** — 自适应 ping 控制器 ✅（`peer/pinger.go`，按会话自启）
2. **gateway/icmp_proxy + ip_reassembler** — ICMP 代理 ✅
3. **peer_center 周期任务** — 中心协调 ✅
4. **peers/graph_algo** — 多路径路由 ✅
5. **peer-RPC 传输/注册/分发** — ✅（`rpc/peer_rpc.go`）
6. **核心运行时接入** — ✅（`core/runtime.go`）

### P1 — 重要功能 ✅

7. **tunnel/fake_tcp 平台实现** — ✅（`faketcp_capture.go` + 默认仿真）
8. **tunnel/wireguard 真实加密** — ✅（`wg_crypto.go` 数据面加密）
9. **peers/peer_ospf_route** — ✅（`route/flood.go` 泛洪 + 收敛）
10. **broadcast 广播转发** — ✅（`broadcast/relay.go`）
11. **upgrade 生产代码** — ✅（`upgrade/upgrade.go`）
12. **smoltcp TCP 校验和** — ✅（`smoltcp/packet.go`）

### P2 — 增强功能（可延后）

9. **publicipv6 NDP/RA** — IPv6 邻居发现
10. **upgrade 生产代码** — 升级与迁移
11. **peers/encrypt 多 cipher** — 多加密算法支持
12. **smoltcp TCP 校验和** — 完整 TCP/IP 栈

---

## 四、各模块 Rust 参考文件索引

| 模块 | Rust 路径 | 行数 |
|------|-----------|------|
| 自适应 Ping | `easytier/src/peers/peer_conn_ping.rs` | 360 |
| ICMP 代理 | `easytier/src/gateway/icmp_proxy.rs` | 491 |
| IP 重组 | `easytier/src/gateway/ip_reassembler.rs` | 324 |
| 图算法 | `easytier/src/peers/graph_algo.rs` | ~200 |
| OSPF 路由 | `easytier/src/peers/peer_ospf_route.rs` | 6676 |
| FakeTCP | `easytier/src/tunnel/fake_tcp/` | ~1500 |
| WireGuard | `easytier/src/tunnel/wireguard.rs` | 923 |
| Peer Center | `easytier/src/peer_center/` | 3 文件 |
| 加密 Cipher | `easytier/src/peers/encrypt/` | ~500 |
| 广播 | `easytier/src/peers/` 相关 | - |
| 公共 IPv6 | `easytier/src/peers/public_ipv6.rs` | - |
