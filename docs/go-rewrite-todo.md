# EasyTier Go 重写：未完成项目清单（2026-08 快照）

> 上游参考：`easytier/src/`（Rust 2.6.4）。本清单只列**未完成/缺失**项；已完成项见 `docs/go-rewrite-gap.md` 顶部状态表。

## 优先级总览

| 优先级 | 模块 | 状态 | 阻塞原因 |
|--------|------|------|----------|
| P0 | peer-RPC 传输/注册/分发 | ✅ 已完成（`rpc/service_ids.go`：SERVICE_ID 常量 1/1/2/7/50、`FuncService`、`CallJSON`/`JSONMethod`；`peer` manager `SetRPCHandler` 流水线；`core` `installRPCPipeline`） | |
| P0 | 核心运行时接入（pinger/icmp/peercenter） | ✅ 已完成（`PingerEnabled` wiring 修复、吞吐量 TX/RX 钩子、`IcmpProxy` 入链、`peercenter.Runner`、`RAAnnouncer`+`LastRA`；修复 pinger/serveManaged 3 处 latent 死锁） | |
| P1 | WireGuard 真实加密隧道 | ✅ 已完成（`wg_crypto.go` 数据面 + `wg_handshake.go` Noise 握手/PFS + `WGSession.Handshake` 会话接入 + `vpnportal` 原生认证） | |
| P1 | upgrade 生产代码 | ✅ 已完成（`upgrade/apply.go`：`Apply` 落盘 0600/备份/校验、`Rollback`、`Migration` 日志） | |
| P1 | smoltcp TCP 校验和 | ✅ 已完成（packet.go 伪头校验和 + buildIPv4Packet 内填充 + buildTCPPacketWithChecksum/buildUDPPacketWithChecksum） | |
| P1 | FakeTCP 完整平台实现 | ✅ 已完成（`faketcp_raw_linux.go` AF_PACKET 真实捕获/注入 + 状态机 + filter；macOS/WinDivert stub + 接口） | |
| P1 | OSPF 路由协议 | ✅ 已完成（`route/ospf_rpc.go` MeshBroadcast + `core` `initFlooder`/`refreshRoutes` 接入，双节点 mesh 0.3s 收敛） | |
| P2 | 节点加密多 cipher | 仅 ChaCha20/AES | 缺 Xor/Null |
| P2 | Windows UDP 广播中继 | 框架 | 平台代码未移植 |
| P2 | GUI 前端集成 | 后端命令 | 前端联调待确认 |

---

## P0 — 阻塞独立运行的模块

### 1. peer-RPC 传输 / 注册 / 分发

**Rust 参考：** `peers/peer_rpc.rs`(347L)、`peers/peer_rpc_service.rs`、`rpc_service/`
**Go 现状：** `internal/rpc/` 仅有 RpcPacket 编解码 + FragmentMerger + 客户端 call；无服务注册表和跨节点分发。

**需要实现：**
- 服务注册（`SERVICE_ID` 常量，如 peer_center=50、logger=…），每个 service 支持本地注册与远端调用
- 请求/响应分发：按 service id 路由到 handler，响应回传原节点
- 接入 `peer.connection_manager` 的 PacketTypeRPCRequest/Response 处理流水线
- 为 peercenter、OSPF、外网客户端提供 `RpcClient<T>` / `RpcServer<T>` 泛型辅助

### 2. 核心运行时接入

**Go 现状：** pinger、IcmpProxy、PeerCenter 已实现但未挂入 `core/runtime.go` 的 node 生命周期；`receiveSession` 中 Ping/Pong 自动应答已有，但无主动 pinger 与延迟统计。

**需要实现：**
- `nodeRuntime` 启动时按 peer 会话创建 `PeerConnPinger`，接 Pong 包、吞吐量钩子（TX/RX）
- 将 `gateway.IcmpProxy` 挂入会话包处理链（Rust `PeerPacketFilter` 等价物）
- `nodeRuntime` 启用 `peercenter.Runner`（get/report 两个周期任务）
- 无 TUN 模式下启动 RA/NDP 通告

---

## P1 — 重要功能

### 3. WireGuard 真实加密隧道

**Rust 参考：** `tunnel/wireguard.rs`(923L, boringtun)
**Go 现状：** `transport/wg.go` 仅合成 WG 头；`vpnportal` 用 mock 握手。

**需要实现：**
- 引入 wireguard-go 级加密（或自实现 Noise_IKpsk2 握手 + ChaCha20Poly1305 数据包）
- WgConfig 解析、对端公钥交换、会话密钥旋转
- 数据面：Type 4 (Data) 包编解码、计数器/重放窗口

### 4. upgrade 生产代码

**Rust 参考：** 无独立模块（launcher 内升级路径）
**Go 现状：** `internal/upgrade/upgrade_test.go`(576L) 验证 Rust→Go 配置迁移确定性，无生产代码。

**需要实现：**
- 版本兼容检查 / 最低版本校验
- 配置迁移：Rust TOML → Go TOML（确定性、权限 0600、RO/NO_DELETE）
- 回滚：Go Dump → Rust 可再解析
- 数据库迁移辅助（append-only、幂等）

### 5. smoltcp TCP 校验和

**Rust 参考：** tokio_smoltcp
**Go 现状：** `internal/smoltcp/packet.go` 用零 TCP 校验和。

**需要实现：**
- TCP/UDP 校验和计算（含 IPv4 伪头）
- RFC 1071 端回进位处理

### 6. FakeTCP 完整平台实现

**Rust 参考：** `tunnel/fake_tcp/`(8 文件)
**Go 现状：** `transport/faketcp.go` 简化实现。

**需要实现：**
- Linux BPF socket 捕获/注入
- macOS BPF、Windows WinDivert 平台适配（可先留 stub + 接口）
- FakeTCP 状态机与对端协商

### 7. OSPF 路由协议

**Rust 参考：** `peers/peer_ospf_route.rs`(6676L)
**Go 现状：** `route/route.go` 扁平 map + Dijkstra。

**需要实现：**
- LSA 通告编解码（复用 `route/advertisement.go`）
- 邻居间 LSA 泛洪（依赖 peer-RPC 传输）
- 路由传播/收敛（`route/convergence.go` 已有基础）

---

## P2 — 增强项

### 8. 节点加密多 cipher
扩展 `peer/secure_datagram.go`：Xor、Null（调试用）、OpenSSL 等价 AES 变体已部分支持。

### 9. Windows UDP 广播中继
移植 `instance/windows_udp_broadcast.rs`(1097L) 的绑定/捕获逻辑到 `broadcast` 包。

### 10. GUI 前端集成
`gui/backend.go` 与 Tauri 前端联调、升级后刷新状态。

---

## 实现顺序建议

```
1. peer-RPC 传输+分发（打通一切）
2. 核心运行时接入（pinger / icmp / peercenter）
3. WireGuard 加密隧道
4. upgrade 生产代码
5. smoltcp 校验和
6. FakeTCP / OSPF（依赖 1 完成后的泛洪）
7. P2 增强项
```

每个模块完成后同步更新 `docs/go-rewrite-gap.md` 状态表。

---

## 实现进度（2026-09，第二轮复验：P0/P1 全部 ✅，`go test ./go/...` 零失败）

| 项 | 状态 |
|----|------|
| peer-RPC 传输/注册/分发（`internal/rpc/peer_rpc.go` + `service_ids.go`） | ✅ 完成 + 测试（含 SERVICE_ID 常量、泛型辅助、manager 流水线） |
| peercenter 实例与周期任务（`internal/peercenter/instance.go`） | ✅ 完成 + 测试 |
| 核心运行时接入（`internal/core/runtime.go`：initCenter/initFlooder/initICMPProxy、packetLoop 分发、close 停止） | ✅ 完成，core 15 项测试通过 |
| pinger 自启与延迟回填（`PingerEnabled` wiring、`PeerLatencyMS` 上报；`tick(ctx)`+满丢包 cancel 死锁修复；Pong 抄送后投递） | ✅ 完成 |
| smoltcp TCP/UDP 校验和（RFC 1071/768，`buildIPv4Packet` 内填充 + WithChecksum  helpers） | ✅ 完成 + 测试 |
| upgrade 生产代码（Version/MakePlan/MigrationCommand + `apply.go` Apply/Rollback/Migration 日志） | ✅ 完成 + 测试 |
| WireGuard 真实加密隧道（`wg_crypto.go` + `wg_handshake.go` Noise 握手/PFS + 会话接入 + portal 原生认证） | ✅ 完成 + 测试 |
| FakeTCP 平台适配（`faketcp_raw_linux.go` AF_PACKET 真实捕获/注入 + 状态机；macOS/WinDivert stub） | ✅ 完成 + 测试 |
| OSPF LSA 泛洪（`route/flood.go` + `ospf_rpc.go` + runtime 接入，双节点 mesh 0.3s 收敛） | ✅ 完成 + 测试 |

**P0/P1 全部完成。剩余工作均为 P2 增强项与已知边界：**
- 节点加密多 cipher（Xor/Null 等，`peer/secure_datagram.go` 目前 ChaCha20-Poly1305；调试用 cipher 可选）
- Windows UDP 广播中继的平台绑定/捕获逻辑移植（`broadcast` 包已有完整转发/过期）
- GUI 前端联调（`gui/backend.go` 后端命令已就绪）
- stock WireGuard 客户端互通（需 boringtun 逐字节兼容握手实现 + 在仓互通对象，外部依赖）