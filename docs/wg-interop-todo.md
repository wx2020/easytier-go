# stock WireGuard 互通实现清单（boringtun 逐字节兼容）

> 目标：Go 端与标准 WireGuard 客户端（WireGuard App、`wg`、boringtun 对端）建连。
> 对照基准：`boringtun-easytier 0.6.1`（`~/.cargo/registry/.../boringtun-easytier-0.6.1/src/noise/`），
> Rust 接入点：`easytier/src/tunnel/wireguard.rs`（`Tunn` + `TunnResult` 状态机）。
> 约定：每项完成后勾选并注明证据（文件+测试）；全部 ✅ 前不通知。

## 阶段 0：原生协议命名空间隔离（前置）

背景：原生握手/数据首字节（1/2/4）与标准 WG 消息类型字节相同但长度语义不同。

- [x] 0.1 原生帧加 magic：在合成 IP 头之后、body 之前加 1 字节 `0xE7`（`transport/wg.go` `sealDatagram`/`openDatagram`、握手 init/resp 收发）
- [x] 0.2 收发两端 demux：crypto 会话下 `0xE7` 走原生、否则走标准解析；无 crypto 保持明文兼容
- [x] 0.3 测试：标准外形报文（148B `0x01…`）不得建立原生会话；既有加密测试全过

## 阶段 1：移植 `Tunn` 核心（`go/internal/transport/wginterop/` 新包）

对照 `noise/handshake.rs`（940L）、`noise/session.rs`（329L）、`noise/mod.rs`（794L，取 responder/数据面子集）。

- [x] 1.1 基础原语：BLAKE2s HASH/MAC（`HASH/N_HASH/MAC` 常量与 label：`Noise_IKpsk2_ChaChaPoly_BLAKE2s`、`WireGuard v1 zx2c4 Jason@zx2c4.com`、`mac1----`）、KDF1/2/3、`mix_hash`/`mix_key`，附 boringtun 已知答案向量测试
- [x] 1.2 Initiation 解析+校验：148B 定长、MAC1（key=`HASH("mac1----"||responder_pub)`，mac 字段置零后算整包）、TAI64N 时间戳解密与去重（TTL 30s 级）
- [x] 1.3 Response 构造：92B、chaining 派生、sender/receiver index 分配
- [x] 1.4 数据面：`[type=4][receiver_index][counter LE]`、nonce=`0×4+counter`、双 Session 并存解密（current/previous）、发送计数器+重放窗口
- [x] 1.5 会话级状态机（responder 最小闭环）：`NewTunn(static_priv)` → `HandleInitiation` → `Encapsulate/Decapsulate`，API 形状对标 `TunnResult::{WriteToNetwork, WriteToTunnelV4/V6, Done, Err}`
- [x] 1.6 Cookie/MAC2 与限流：`rate_limiter.rs` 对等实现（负载下 MAC2 路径），或显式记录降级行为

## 阶段 2：接入 portal/transport

- [x] 2.1 `vpnportal` serve 循环 demux：标准外形报文进 `wginterop.Tunn`，原生报文走现有 `nativeCrypto`
- [x] 2.2 `WriteToTunnelV4/V6` 明文 IP 包转交 PeerManager（对标 `wireguard.rs:232`），`WriteToNetwork` 回写 UDP（含 endpoint 漫游更新）
- [x] 2.3 密钥来源：`GetWgConfig` server seed 即 responder 静态私钥（与 Rust `new_for_portal` 同源）
- [x] 2.4 `transport` 侧（可选，若 portal 闭环已满足验收则记为后续）：`WGSession` 标准模式 —— portal 闭环已满足验收，记为后续（mesh 内 WG 传输仍用原生加密路径）

## 阶段 3：互通验证

- [x] 3.1 Golden 向量：boringtun 已知答案测试移植为 Go 测试（握手 KDF 链、MAC1、数据包加解密）
- [x] 3.2 真实对端集成测试：wireguard-go 或 `wg` 工具作对端 → portal 建会话 → 双向 ping（无 root/`wg` 缺失时 skip，成功时不断言豁免）
- [x] 3.3 负向测试：错 key 静默丢弃、重放 initiation 去重、MAC2/cookie 路径
- [x] 3.4 全量回归：`go test ./go/...` 零失败；`go vet`/`gofmt` 干净

## 验收结果（2026-09-11）

- 3.2 硬门槛通过：`TestBoringtunProbeInterop`——真实 boringtun-easytier `Tunn` 作 initiator，经 portal 完成握手并双向通包（`probe: echo OK`）。
- 本文档 checklist 全部 ✅（2.4 为显式可选后续项）。

## 验收标准

- stock 客户端可经 portal 建会话并双向通包（3.2 为硬门槛，失败则整体未完成）。
- 本文档 4 阶段 checklist 全部 ✅。
