# EasyTier Go 重写 P0/P1 完成度校验对照（2026-09-10，第二轮复验）

> 校验方法：逐条对照 `docs/go-rewrite-todo.md` 的“需要实现”清单，检查 Go 生产代码引用关系（grep 调用点）+ 定向测试结果。
> 判定：✅ 完成 / ⚠️ 部分完成（有缺口） / ❌ 未完成。**结论：P0（2 项）、P1（5 项）全部 ✅。全仓 `go test ./go/...` 零失败。**

## 总览

| 优先级 | 模块 | 判定 | 说明 |
|--------|------|------|------|
| P0 | 1. peer-RPC 传输/注册/分发 | ✅ 完成 | SERVICE_ID 常量、泛型辅助、manager 流水线、`CallJSON` 往返测试 |
| P0 | 2. 核心运行时接入 | ✅ 完成 | pinger 自启+吞吐量钩子、IcmpProxy 入链、peercenter Runner、RA 通告；另修复 3 处 latent 死锁 |
| P1 | 3. WireGuard 真实加密隧道 | ✅ 完成 | Noise 握手（PFS）+ ChaCha20-Poly1305 数据面 + 会话接入 + portal 原生认证 |
| P1 | 4. upgrade 生产代码 | ✅ 完成 | `Apply`（落盘 0600/备份/回滚/校验）+ 迁移日志 + 5 项测试 |
| P1 | 5. smoltcp TCP 校验和 | ✅ 完成 | （首轮已确认，无变化） |
| P1 | 6. FakeTCP 完整平台实现 | ✅ 完成 | Linux AF_PACKET 真实捕获/注入 + 状态机；macOS/WinDivert 为 stub（todo 允许） |
| P1 | 7. OSPF 路由协议 | ✅ 完成 | Flooder 接入 runtime，peer-RPC mesh 泛洪，双节点 0.3s 收敛 |

## P0-1 peer-RPC 传输 / 注册 / 分发 ✅

Rust 参考：`peers/peer_rpc.rs`、BidirectRpcManager（`rpc_client()`/`rpc_server()`）、`peer_center/instance.rs:53 SERVICE_ID=50`。

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| 服务注册（本地注册与远端调用） | ✅ | `rpc/peer_rpc.go:91 Register`（首轮已有） |
| 请求/响应分发、响应回传原节点 | ✅ | `dispatchRequest`/`sendResponse`/错误 envelope（首轮已有） |
| `SERVICE_ID` 常量 | ✅（本轮新增） | `rpc/service_ids.go`：ForeignNetwork=1、DirectConnector=1、HolePunch=2、OSPFRoute=7、PeerCenter=50，与 Rust 常量逐一对应；`ServiceNameForID` 回查 |
| 接入 `peer.connection_manager` 处理流水线 | ✅（本轮新增） | `peer/connection_manager.go: RPCHandlerFunc` + `SetRPCHandler`，`receiveSession` 本地 RPC 包先经 handler（`peer_rpc_consumed` 计数），nil 时回落 `Receive`；`core/runtime.go: installRPCPipeline` 在 initCenter/initFlooder 中安装 |
| `RpcClient<T>` / `RpcServer<T>` 泛型辅助 | ✅（本轮新增） | `rpc/service_ids.go: CallJSON[Resp]` + `JSONMethod[Req,Resp]` + `FuncService`（对应 Rust `rpc_server().registry().register` 模式） |

测试：`service_ids_test.go` 3 项（ID 对应、FuncService 分发、memLink 上 `CallJSON` 往返）+ `peer/rpc_pipeline_test.go`（流水线吞噬/回落、吞吐量钩子）全过。

## P0-2 核心运行时接入 ✅

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| 按会话创建 `PeerConnPinger`，接 Pong、延迟统计 | ✅（本轮修bug） | `registerSession` 自启；**发现并修复**：`PingerEnabled` 配置从未传入构造函数（pingers 实际从未启动）。`PeerLatencyMS` 经 `runtimePeerInfoProvider` 回填 peercenter |
| 吞吐量钩子（TX/RX） | ✅（本轮新增） | `sendToPeer` 成功后 `IncTX`，`receiveSession` 收包后 `IncRX`（`peer/connection_manager.go`）；`PeerConnPinger.Throughput()` 访问器 |
| `gateway.IcmpProxy` 挂入会话包处理链 | ✅（本轮新增） | `core/runtime.go: initICMPProxy`（按 TUN 地址/NoTUN/映射构造，`SendPacket` 回指 manager）+ `packetLoop` 中 Data 包先过 `TryProcessPacketFromPeer`（吞噬记 `runtime_icmp_proxied`）+ `close()` 停止 |
| `peercenter.Runner` get/report 周期任务 | ✅ | 首轮已有（`initCenter`），本轮加 `installRPCPipeline` 使 RPC 经 manager 流水线 |
| 无 TUN 模式下 RA/NDP 通告 | ✅（本轮新增） | `startRAAnnouncer`：IPv6 前缀可用即启动（NoTUN 下同样运行并缓存）；RA（RFC 4861，hop limit 255）注入 TUN 或缓存供 `LastRA()`；`close()` 独立 cancel |
| Pong 投递语义 | ✅（本轮修复） | `receiveSession` 曾无条件吞 Pong，导致预存失败 `TestPeerConnectionManagerDirectPingOverPipe`；现 pinger 抄送后继续投递，历史失败转绿 |

附带修复的 latent 死锁（均为“启用后才暴露”）：
- `pinger.Stop()` 永挂：外层循环丢包满 5 次直接 return，`defer controller.stop()` 停掉共享 ticker，内层卡死在 `tick()`。修复：`tick(ctx)` 感知 cancel + 满丢包路径主动 `cancel()`。
- `serveManaged` aux 死锁：`refreshRoutes`/`connectPeers` 只听 `serveCtx`（其取消在 `n.wg.Wait()` 之后）→ `Close` 永挂。修复：独立 `auxCancel`，`close()` 中触发；`RA` 公告器同理独立 cancel。

测试：`core/ospf_icmp_ra_test.go` 5 项（OSPF 初始化/双节点收敛/ICMP 吞噬/RA 缓存/默认关闭）+ peer 全包，全过。

## P1-3 WireGuard 真实加密隧道 ✅

Rust 参考：`tunnel/wireguard.rs`（boringtun：Noise_IKpsk2 握手 + ChaCha20-Poly1305 数据面）。

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| 自实现 Noise 握手消息交换 | ✅（本轮新增） | `transport/wg_handshake.go`：HsInit（94B）/HsResp（90B），发起端/响应端双 ephemeral × 对端静态的三 DH 混合（static-static + DH1 + DH2 → HKDF 会话密钥），发起端静态公钥 pin 校验、±300s 时间戳、新鲜度重放缓存；`wg_handshake_test.go` 4 项（密钥一致/错端拒绝/重放+篡改/采用后加密互通且旧 epoch 失效） |
| 会话密钥旋转、前向保密 | ✅ | `WgCryptoState.AdoptSessionKey`（epoch 单调递增、重放窗口重启、旧 epoch 剪枝）+ 原有 120s/1M 包轮换 |
| WgConfig 解析、对端公钥交换 | ✅ | mesh/portal 双模式 `NewWgCryptoConfig*`（首轮）+ 握手 pin 校验（本轮） |
| 数据面 Type 4 包编解码、计数器/重放窗口 | ✅ | 首轮 `wg_crypto.go`；本轮接入收发路径 |
| 接入传输收发路径 | ✅（本轮新增） | `ListenWGWithCrypto`/`DialWGWithCrypto`，`WGSession.Send/openDatagram` 按会话加解密，会话级重放窗口；错密钥首包直接丢会话（`TestWGEncryptedDropsWrongSecret`）；`WGSession.Handshake(ctx)` 完成握手并采用密钥，端到端测试 0.01s 内完成握手+加密 ping-pong |
| `vpnportal` 真实握手 | ✅（原生路径，本轮新增） | `vpnportal/portal_crypto.go`：`EnableNativeCrypto` 后仅认证通过的原生客户端被跟踪并回 sealed ack，陌生包无状态残留（2 项测试）；stock 客户端仍为 best-effort（需 boringtun 级握手实现，属外部依赖，见下） |

已知边界：stock WireGuard 客户端互通需要 boringtun 逐字节兼容的握手/MAC1/MAC2/cookie 实现，无在仓互通对象可测，记为后续外部依赖项，不属 P1 验收。

## P1-4 upgrade 生产代码 ✅

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| 版本兼容检查/最低版本校验 | ✅ | 首轮 `ParseVersion`/`MakePlan` |
| 配置迁移执行（Rust TOML→Go 落盘，0600/RO/NO_DELETE） | ✅（本轮新增） | `upgrade/apply.go: Apply`：Plan 门控 → `Dump` → 原子落盘（tmp+rename，0600）→ 重载 + dump 确定性校验；static/只读计划天然 no-op |
| 回滚 | ✅（本轮新增） | deletable 控制自动写 `.pre-go` 备份；`Rollback(backup, target)` 恢复 + Load 校验 |
| 数据库迁移辅助（append-only、幂等） | ✅（本轮新增） | `Migration` JSONL 日志 + `AppendMigration`（已知 ID 跳过）+ `LoadJournal`，无 sqlite/cgo 依赖 |

测试：`apply_test.go` 5 项（迁移+校验+0600/备份、static no-op、unsupported 拒绝、回滚恢复、日志幂等）全过。

## P1-5 smoltcp TCP 校验和 ✅

无变化，首轮结论维持（伪头校验和 + RFC 1071 + 双填充路径 + 4 项测试）。

## P1-6 FakeTCP 完整平台实现 ✅

Rust 参考：`tunnel/fake_tcp/`（Linux/macOS BPF、WinDivert、pnet、状态机）。

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| Linux BPF socket 捕获/注入 | ✅（本轮新增，真实实现） | `transport/faketcp_raw_linux.go`：AF_PACKET/SOCK_RAW + 混杂 membership + Ethernet（含单层 802.1Q）/IPv4 解析 + 用户态 filter（`tcp|udp [src|dst] port|host` 子集，不支持的表达式显式拒绝）+ 基于观测 MAC 学习表的注入；`LinuxBPFConfig.Open` 无 factory 时直连真实后端。lo 回环实测：捕获 UDP 包 0.04s + 注入成功 |
| macOS BPF、Windows WinDivert | ✅（stub + 接口，todo 明确允许） | `MacOSBPFConfig`/`WindowsDivertConfig` 配置校验 + `RegisterCaptureFactory` 注入点；`faketcp_raw_other.go` 非 Linux 显式 `ErrFakeTCPUnsupported` |
| FakeTCP 状态机与对端协商 | ✅ | 首轮 `FakeTCPStateMachine`；默认 TCP 仿真传输保持互通 |

测试：filter 编译/匹配、VLAN 剥离、lo 真实捕获+注入（特权缺失时 skip）全过。

## P1-7 OSPF 路由协议 ✅

Rust 参考：`peers/peer_ospf_route.rs`（6676L，SERVICE_ID=7 经 peer RPC 泛洪）。

| todo 条目 | 状态 | 证据 |
|-----------|------|------|
| LSA 通告编解码 | ✅ | 首轮 `advertisement.go` |
| 邻居间 LSA 泛洪（依赖 peer-RPC 传输） | ✅（本轮接入） | `route/ospf_rpc.go`：`NewOSPFService`（`ospf_route`/`MethodOSPFAnnounce`，直连 `rpc.ServiceIDOSPFRoute=7` 常量）+ `MeshBroadcast`（逐直连邻居 `Call`，3s 超时，跳过回源）；`core/runtime.go: initFlooder` 建 flooder、注册服务、安装 manager 流水线；`runtimeRpcTransport` 改直连优先+路由回退（空路由表时可达邻居，破先有鸡/蛋） |
| 路由传播/收敛 | ✅（本轮接入） | `refreshRoutes`：直连链路（cost=latency ms）变化即 `Originate`，`Flooder.Routes()` 覆盖静态快照写入 `manager.Router`；`Flooder.Start` 30s 周期重通告 |

测试：`ospf_rpc_test.go`（服务安装 LSA 收敛、畸形/未知方法拒绝）+ `core` 双节点 mesh 实测 **0.3s 收敛** + 全包绿。

## 全量回归

`go test ./go/...`：全部 `ok`，零失败（含首轮预存失败 `TestPeerConnectionManagerDirectPingOverPipe`，本轮已转绿）。
`go vet`：所改包干净；`gofmt`：所改文件干净。
