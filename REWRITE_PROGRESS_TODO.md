# Go 重写进度 TODO（基于 71e79a8 静态分析）

> 生成日期：2026-09-11。
> 方法：对照 Rust oracle（`easytier/` 2.6.4，commit 8428a89d）逐模块盘点 `go/` 实现，
> 并结合 GitHub Actions 实际运行结果（run 34613259861 `Go`、34613259972 `Rust-Go Interop`）。
> 遵循 `docs/CLEAN_ROOM.md`：补齐差距必须从 `docs/GO_REWRITE_SE.md` 规范与
> `go/testdata/compat/` 金标准向量出发实现**行为对齐**，禁止逐行翻译 Rust 源码。

## 1. 总体状态

| 维度 | 状态 |
| --- | --- |
| Go 代码量 | 265 文件 / ~61,700 行（不含 `*.pb.go`），38 个 `internal/` 包 + 5 个子模块（web/ffi/jni/platform/uptime） |
| Rust oracle | ~95,000 行（`easytier/src`，含 8.5k 测试） |
| 编译/vet | `go.yml` 迁移后首跑**失败**（gofmt 未格式化，340 文件）→ 本次已修，待 CI 复验 |
| 测试 | `go test -race ./...` 在 `internal/core` 检出 **3 处数据竞争** → 本次已修，待 CI 复验 |
| 互通（interop） | `interop.yml` 的 oracle 构建在 checkout 阶段失败（squash 后仓库无 8428a89d）→ 本次已改从上游 `EasyTier/EasyTier` 检出；`docs/GO_REWRITE_TODOLIST.md` VAL-02 自认仅 1 个互通单元（tcp/legacy go_to_rust）为绿 |
| 单元测试覆盖 | 各包均有 `_test.go`；`interop/` 包 3378 行提供跨实现对照 |

**结论**：工程骨架与大部分数据面（TCP/UDP/WS/WSS/Unix/WG 隧道、包编解码、加密会话、
配置加载、CLI 面、管理 RPC、web 控制面）已有实质实现并有测试；**与 Rust 的互通面
（OSPF 路由线协议、UDP 打洞、NAT 分类、peer-center 线格式）与文档声称的 complete
不符，是当前最大的完成度风险**。

## 2. 本次已静态修复（待 CI 验证）

1. **gofmt**：`gofmt -w go/` 修复全部 340 个不合规文件（`go.yml` 第一步即失败）。
2. **数据竞争 ×3**（`go/internal/core/runtime.go`、`ospf_icmp_ra_test.go`）：
   - `nodeRuntime` 新增 `stateMu sync.RWMutex`，`ospf`/`peerRPC`/`icmpProxy`/`center`/`raProvider`/`raCancel`
     的 init 发布点与 `close()` 读取全部加锁；新增 `OSPF()`/`PeerRPC()` 访问器，测试改用访问器。
   - `serveManaged` 中 `tunPackets` 通道创建移至 `startRAAnnouncer` 之前，
     消除 `announceRA` 与启动序列的写读竞争（CI 报告 race @ runtime.go:448 ↔ :1111）。
3. **`.github/workflows/interop.yml`**：oracle 改为双 checkout（本仓库 + 上游
   `EasyTier/EasyTier@8428a89d` 至 `oracle/` 子目录），build/cache/artifact 路径同步调整；
   artifact 根目录结构不变，消费端 `/tmp/easytier-core*` 兼容。
4. 新增根目录 `AGENTS.md`（后续 agent 的仓库须知）。

## 3. 逐模块完成度

图例：✅ 完整（有实现+测试）　🟡 部分　🔴 缺失/仅原型　❓ 未验证（需互通测试）

### 3.1 传输层（Rust `tunnel/` ~11.3k 行 → Go `internal/transport/` ~8k 行）

| 隧道 | 状态 | 说明 |
| --- | --- | --- |
| TCP / UDP(SYN+SACK) / WS+WSS / Unix | ✅ | 与 Rust 对应实现+测试齐备；UDP 打洞包构造在 `internal/nat` |
| WireGuard `wg://` | 🟡 | 数据面/握手/MAC2 cookie/重放窗口齐备；**缺 boringtun 式会话到期 rekey/轮换**，仅空闲 TTL 回收 |
| QUIC | 🔴 | `quic.go` 自述为“plaintext QUIC-like **for testing**”，非真 QUIC，**与 Rust quinn-plaintext 无法互通**。TODOLIST 表格标 complete、§7.7 又标 blocked，自相矛盾——按 blocked 计 |
| fake_tcp | 🟡 | 默认路径是 TCP 仿真回退（Go-Go 专用，非线协议）；Linux AF_PACKET 原始抓包可用；**缺 Windows WinDivert、macOS BPF** |
| ring（测试用内存隧道） | 🔴 | 无对应物（低优先级） |
| `bind`/BindDev 绑定网卡 | 🔴 | Go 侧无 SO_BINDTODEVICE 等价物 |
| wss 自签证书（insecure_tls.rs） | 🔴 | 无对等路径 |

### 3.2 对等层/路由/NAT（Rust `peers/`+`connector/` ~34k 行 → Go `peer/ route/ nat/ …` ~12k 行）

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| 连接管理、ping/时延、限流 | ✅ | `peer/connection_manager.go` 等 |
| Noise 加密会话（AEAD/重放窗口/epoch） | ✅ | `peer/secure_datagram.go`、`direct_noise_handshake.go` |
| **旧版全局加密（xor/aes-gcm）** | 🔴 | 仅 proto 枚举存在，无实现——Rust 兼容模式互通会失败 |
| **OSPF 路由** | 🟡🔴 | 计算/收敛/图算法有实现+金标准测试；但线协议是**自定义 JSON 泛洪**，非 Rust `OspfRouteRpc` protobuf——**Go↔Rust 路由扩散不互通**；缺信任凭证证明、重复 peer 检测、exit-node 路由信息 |
| Peer RPC 骨架 | 🟡 | 域/服务/方法索引+分片+压缩可用；Rust 各 proto 服务（如 peer_direct_access）大多未注册 |
| 中继/令牌桶/白名单 | 🟡 | `relay/` 存在；Rust foreign-network 客户端自动连接面（~2700 行）大部分缺失 |
| Peer center | ✅❓ | 结构完整并入 runtime；但 JSON 线格式 vs Rust protobuf `PeerCenterRpc`，互通未验证 |
| **UDP 打洞** | 🔴 | `nat/hole_punch.go` 仅原语（载荷编解码/端口预测）；cone/sym-to-cone/easy-sym/both-sym 四策略引擎与协调器无实现，`PunchHole` 等 proto 生成后**从未被引用** |
| TCP 打洞 | 🟡 | 同时连接+回退监听有；打洞套接字未升级为已认证 peer 会话 |
| 直连连接器（global map 驱动） | 🔴 | 无地址发现/拨号循环；connector 包未接入 `core/runtime.go` |
| STUN/NAT 分类 | 🔴 | 223 行 bind-only 客户端；无 RFC5780 行为探测与 NatType 判定，未接入 runtime |
| UPnP/NAT-PMP 映射 | ✅❓ | `mapping/` 有实现+测试，互通待验证 |
| public_ipv6 / NDP | ✅ | `publicipv6/` |

### 3.3 实例/网关/管理面（Rust `instance/ gateway/ rpc_service/` → Go `core/ gateway/ management/ …`）

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| CLI flag 面 | ✅ | 82 个 Rust 选项 ↔ Go 81+ flag 全覆盖（含 `--check-config/--daemon/--disable-env-parsing` 与全部 `ET_*` 环境变量映射）；Go 另有 `--listen`、`--quic-listen-port`、`--multi-thread`、`--need-p2p`、`--disable-relay-data` 等 Rust 2.6.4 无的兼容别名 |
| TOML 配置加载/校验/`${VAR}` 展开 | ✅ | `config/` + 金标准 config fixtures |
| TUN / smoltcp 栈 | ✅ | `tun/`(1243 行) + `smoltcp/`(2871 行, 12 文件) |
| ICMP 代理 / IP 重组 | ✅ | `gateway/icmp_proxy.go`、`ip_reassembler.go` |
| KCP / QUIC 代理（网关侧） | ✅❓ | `gateway/kcp.go`、`quic.go`、`lossy.go`；与 Rust 互通未验证 |
| socks5 服务 | ✅ | `internal/socks5/` |
| 管理 RPC 服务 | ✅ | `management/` 覆盖 ACL/配置/连接器/凭证/DNS/转发/实例/日志/映射监听/peer/route/stats/VPN portal/web 会话——对应 Rust 16 个 rpc_service 文件 |
| web 控制面 | ✅❓ | `go/web/`（独立模块：server/handlers/store/captcha/迁移）+ `webclient/`；与 Rust web 契约互通未验证 |
| VPN portal (wg) | ✅❓ | `vpnportal/`（1570 行） |
| 平台层（服务安装/路由/DNS） | ✅ | `internal/platform`(2616) + `go/platform` 子模块，含 dry-run planner 测试 |
| FFI / JNI / Magisk / OHOS | ✅❓ | `go/ffi`(含 stub)、`go/jni`、`cmd/gen-magisk`；产物级验证待发布流水线 |

### 3.4 与 `docs/GO_REWRITE_TODOLIST.md` 声称的出入

| 行项 | 文档声称 | 实际观察 |
| --- | --- | --- |
| NET-06 `wg://` | complete | 基本属实（缺 rekey） |
| NET-07 QUIC | complete 且 §7.7 blocked | 按 **blocked** 计：测试替身，无互通 |
| NET-08 fake-TCP | complete | 仅 Linux 真实抓包；WinDivert/macOS BPF 缺失（与 §NTV-06 矛盾） |
| P2P-02 STUN/NAT 分类 | complete | **不成立**：bind-only |
| P2P-03 UDP 打洞四策略 | complete | **不成立**：仅原语 |
| P2P-05 OSPF | complete | 计算面成立；**线协议不互通** |
| VAL-02 | 仅 1 个互通单元绿 | 与本分析一致，应以 VAL-02 为准 |

## 4. TODO 清单（按优先级）

### P0 — 恢复并夯实 CI 绿线（本次已做，需 CI 复验确认）
- [ ] `go.yml` 全绿：gofmt（已修）→ `go vet` → `go test -race`（race 已修）→ 双平台构建。
- [ ] `interop.yml` build-oracle 恢复（已改上游 checkout）；观察 fixture-corpus 与第一个互通单元。
- [ ] 若 CI 报出新错误：按报错逐个修复（以 CI 为编译器，本地不编译）。

### P1 — 线协议互通（决定“100% 功能”能否成立）
- [ ] **OSPF 线协议对齐**：改用生成的 `OspfRouteRpc`/`SyncRouteInfo`/`RoutePeerInfo` protobuf
  （`internal/proto` 已有绑定）替换 JSON 泛洪；补信任凭证证明、重复 peer 检测、exit-node 字段。
  用 `go/testdata/compat/route` 增加金标准向量后重写 `route/` 序列化层。
- [ ] **旧版加密（xor / aes-gcm）**：按 SE §4 会话规范实现 legacy EncryptionMethod 协商与数据面；
  `go/testdata/compat/secure` 建向量。
- [ ] **peer-center 线格式**：`PeerCenterRpc` protobuf + GlobalPeerMap 二进制编码对齐。
- [ ] **QUIC**：接真 QUIC（建议 quic-go + 与 Rust quinn-plaintext 对齐的 TLS 设置或 plaintext 扩展），
  或在 TODOLIST/README 明确宣布 Go 产品矩阵不含 QUIC 隧道（移除 `quic://` scheme 以免误配）。

### P2 — 打洞与直连（Rust 核心卖点，当前缺失）
- [ ] STUN RFC5780 行为探测 + NatType 分类（`common/stun.rs` 为行为规范），接入 runtime。
- [ ] UDP 打洞协调器 + cone / sym-to-cone / easy-sym / both-sym 四策略（`udp_hole_punch/` 为规范）；
  打通生成的 `PunchHole/NatType/SendPunchPacketEasySym` proto 服务。
- [ ] 打洞/TCP 打洞成功套接字升级为已认证 peer 会话。
- [ ] 直连连接器：peer-center GlobalPeerMap → 地址发现 → UDP punch/TCP dial 循环；
  把 `connector/`、`mapping/`、`stun/` 接入 `core/runtime.go` 启动序列。
- [ ] Manual 连接器管理。

### P3 — 传输层补全
- [ ] WG 会话 rekey/keepalive 轮换（boringtun expiry 语义）。
- [ ] fake_tcp：Windows WinDivert 与 macOS BPF 原始抓包（对照 `tunnel/fake_tcp/` 行为）。
- [ ] wss 自签证书拨号路径（insecure_tls 行为）。
- [ ] bind-to-device（`BINDTODEVICE`/IP_BOUND_IF/IP_UNICAST_IF）。
- [ ] ring 内存隧道（仅测试便利，最低优先）。

### P4 — 验证与文档
- [ ] `docs/GO_REWRITE_TODOLIST.md`：把 NET-07/NET-08/P2P-02/P2P-03/P2P-05 状态改为实测值
  （complete → partial/blocked），消除与 VAL-02 的自相矛盾。
- [ ] 为每个 P1/P2 项先补 Rust oracle 金标准向量（`tools/gen-fixtures`），再实现 Go 侧。
- [ ] `go test -race ./...` 在 Linux CI 全绿后，跑 `interop.yml` 全矩阵（tcp/udp/wg/wss ×
  legacy/noise × 双向），全部绿后才可声称功能对齐（SE §2 第 6 条契约）。

## 5. 复验命令（全部经 GitHub Actions，本地不编译）

```bash
git push origin <branch>          # 触发 go.yml + interop.yml
gh run watch -R wx2020/easytier-go <run-id>
gh run view -R wx2020/easytier-go <run-id> --log-failed
```
