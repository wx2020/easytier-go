# AGENTS.md

## What this repo is

EasyTier — a decentralized mesh VPN — with an in-progress **clean-room Go rewrite** on branch `feature`. The Rust source (EasyTier 2.6.4) is kept as the **compatibility oracle/spec only**; the active product is the Go implementation under `go/`. Read `docs/CLEAN_ROOM.md` and `docs/GO_REWRITE_SE.md` before touching `go/`.

## Layout

- `go/` — Go rewrite (main module): `cmd/easytier-core` (daemon), `cmd/easytier-cli`, `internal/*` (acl, config, connector, core, instance, nat, peer, proto, rpc, transport, tun, …)
- `go/web`, `go/ffi`, `go/jni`, `go/platform`, `go/uptime` — **separate Go modules**, joined via root `go.work`
- `easytier/` — Rust core crate (oracle; do not modify to "fix" Go parity)
- `easytier-gui/` — Tauri desktop GUI (Vue/Vite frontend in `easytier-gui/`, Rust in `src-tauri/`)
- `easytier-web/` — Rust web backend + `frontend/`, `frontend-lib/` (pnpm workspace)
- `easytier-contrib/` — Rust FFI/uptime/android-jni/ohrs
- `tools/gen-fixtures` — Rust golden-fixture generator
- `go/testdata/compat/` — committed golden vectors (packet, handshake, noise, config, …); **source of truth**
- `docs/` — `CLEAN_ROOM.md` (policy), `GO_REWRITE_SE.md` (spec + §11 migration records), `GO_REWRITE_TODOLIST.md` (work breakdown with IDs), `RUNBOOK.md`

## Clean-room rules (non-negotiable for `go/`)

- Never copy Rust source text, comments, struct layouts, or control flow into Go. Implement from specs in `docs/GO_REWRITE_SE.md` and black-box fixtures in `go/testdata/compat/`.
- Every Go file needs the SPDX header (`// SPDX-FileCopyrightText: 2025 EasyTier Contributors` / `// SPDX-License-Identifier: LGPL-3.0-only`), after any build tags / generated-code notices.
- Generated `*.pb.go` keeps its `DO NOT EDIT` notice; do not hand-edit. Protobuf field numbers are locked (verified by `TestDescriptorFieldNumbers`).
- Intentional protocol/behavior divergence requires a migration record in `GO_REWRITE_SE.md` §11.
- Wire contracts are frozen: 16-byte little-endian `PeerManagerHeader`, Noise prologue `easytier-peerconn-noise`, config TOML field names/defaults, `ET_*` env vars, `${VAR}`/`${VAR:-default}` expansion.

## Build & test

Go (run from `go/`; CI uses `GOWORK=off` there — go.work is for the sub-modules):

```bash
cd go
go build ./cmd/easytier-core ./cmd/easytier-cli
go vet ./...
go test -race ./...
gofmt -l .   # must be empty; CI fails on diffs
```

- Release-style builds: `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid=" …`
- Fixture corpus is committed; regenerating (`tools/gen-fixtures`) must produce zero diff or a §11 migration record — CI fails otherwise.
- Rust core: `cargo build --release` (default members: `easytier`, `easytier-web`); tests: `cargo test --no-default-features --features=full` (needs Linux bridge/netfilter sysctls; full suite is Linux-only).
- Frontend/GUI: `pnpm -r install`; `pnpm -r build`; `cd easytier-gui && pnpm tauri build`. Needs Node 21+/pnpm 9, protoc for Rust builds.
- Toolchains: Rust 1.95 (`rust-toolchain.toml`), Go per `go.work` (1.25), protoc 3.21.12.

## Architecture boundaries (`go/`)

- `internal/peer` must never import OS-specific code; platform differences go through interfaces (`internal/platform`, `go/platform` adapters).
- Everything runs under context-bound lifecycles: no goroutines outside the owning context; every socket/TUN FD/route/timer needs a close path.
- Packet paths use bounded queues with explicit drop counters; config is published as immutable snapshots.
- Version/ldflags: binaries embed `main.version`/`main.commit`; root `VERSION` file (2.6.4) is the source of truth.

## Conventions

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- PRs target branch `feature` (the repo's only/default branch) and should reference a ToDo ID from `docs/GO_REWRITE_TODOLIST.md` plus unit and golden-vector tests.
- CI gates: `go.yml` (fmt/vet/test-race/build + cross-build), `interop.yml` (Go↔Rust 2.6.4 bidirectional interop + fixture corpus), `reuse lint`/SPDX checks.
- On Windows, TUN/platform-dependent tests are limited; full integration runs on Linux.

## Live interop & deployment (2026-10-20)

- Reference LuCI app to mirror for `luci-app-easytier`: `C:\Users\J6001887\Code\mine\mu300-magisk-v2026.10.20-openwrt-luci-k6.18\luci-app-singbox\` — standalone ipk builder (`build.sh` → debian-binary + control/data tar), `control/{control,postinst,postrm}`, `root/usr/share/luci/menu.d/*.json`, shell CGI at `root/www/cgi-bin/singbox-api`, view at `root/www/luci-static/resources/view/singbox/dashboard.js`.
- Target nodes and access facts live in the global memory section `EasyTier 线上联调节点`.
- 2026-10-20: three tasks (fill project gaps → live interop with official EasyTier on 100.64.0.2 → develop/deploy LuCI app on the F50 at 192.168.0.1) dispatched to session `ses_ea77f9013ffee9ZLiglEb2cAut` (build). Do not restart or modify the live easytier instance on 100.64.0.2; interop must add a temporary peer only and snapshot peer counts before/after.
- Known gaps at dispatch time: QUIC `go_to_rust` cells hang ~10 min (`quic.go:184` → `quicwire/conn.go:108` → `quicwire/stream.go:148`); release workflow `assemble` fails; Magisk/Android/OHOS/GUI artifacts are placeholders; README claims "100%".
- 2026-10-20 baseline facts (verified read-only before changes):
  - `100.64.0.2` = qcloud-sh, Ubuntu 22.04 x86_64, network `10.64.0.0/24` (local node `10.64.0.1/24`), `easytier-core 2.6.4-8428a89d` started as `/usr/local/bin/easytier-core -w udp://easytier.wx2020.cn:22020/wx2020` (web-managed, config in `/root/config/easytier/et.db`, not `/etc`), binaries symlinked from `/root/software/easytier-linux-x86_64/`, listeners tcp/udp 11010, wg 11011, wss 11012, RPC 15888; 7 peers (10.64.0.1–.9). Baseline saved at `.tmp/dispatch-verify/baseline-100.64.0.2.txt`.
  - `192.168.0.1` = F50 OpenWrt 25.12.5, **package manager is `apk` (apk-tools 3.0.5), `opkg` does not exist** ⇒ `.ipk` cannot be installed; `luci-app-singbox` on the device was deployed as plain files, not via apk. Deploy the LuCI app by copying `menu.d/*.json`, `www/luci-static/resources/view/easytier/*.js` and `www/cgi-bin/easytier-api`, or build an `.apk`. Theme `aurora`, uhttpd on 80/443, no easytier installed at baseline.
- 2026-10-20: 15 分钟自动巡检已建（OpenChamber schedule `6e1ed216-d729-419e-9420-829fb4c0d1ca`，cron `*/15 * * * *`，Asia/Shanghai，targetSession = 本会话）：busy 只记一行；idle 且报错则向 `ses_ea77f9013ffee9ZLiglEb2cAut` 发断点续跑；正常结束但缺证据则发剩余任务；三项齐全则记「巡检通过」。

### 2026-10-20 execution results (three tasks)

- **Task 1 (project gaps)**: `docs/GO_REWRITE_TODOLIST.md` now reports **46 complete / 17 in-progress** (63 rows); README/README_CN no longer claim 100%. `go-release.yml`: Go 1.25.0, 5-target matrix (linux amd64/arm64, freebsd amd64, windows amd64/386), `gh run download` retry loop, Android/Magisk/OHOS/GUI placeholder jobs removed and recorded in `DEFERRED.md`. `mobile.yml` rewritten to a Go JNI/arm64 validation workflow. `gen-magisk` now requires a real ELF and sets 0755 in the zip. QUIC receive is context-aware (`quicwire.ReadContext` + `quicContextReader`), with `TestQUICSessionReceiveHonorsContext`; the four `quic/*/go_to_rust` cells are marked experimental and `interop-result` now blocks for every non-experimental failure. Windows socks5/upgrade tests fixed. Local: `go test ./...`, `go vet ./...`, `go test -race ./...` green; changed-file gofmt clean.
- **Task 2 (live interop)**: Go `v2.6.4-gointerop4` joined the live `wx2020` network (TCP and UDP variants) through a temporary Rust 2.6.4 oracle on `100.64.0.2`; the live node was not restarted or reconfigured. Before/after: PID 248211 and 7 peers unchanged; temp processes/files removed. Fixed four runtime bugs: random per-start peer ID, management `node` ID, CLI `EnableOSPF`, and OSPF self-description fields (hostname/IPv4/IPv6/version/TCP NAT). Evidence: `docs/INTEROP_LIVE_100.64.0.2.md`, `GO_REWRITE_SE.md` §11.5. Note: Task 3 later adds the F50 as an intentional permanent 8th peer.
- **Task 3 (LuCI + F50)**: new `luci-app-easytier/` (Makefile, control, procd init, menu.d, shell CGI, LuCI view, `build.sh`); `build.sh` emits `.ipk`, plain-file tarball, and arm64 binaries. The F50 is **apk-based (no opkg)**, so it was deployed as plain files; the `.ipk` is for standard OpenWrt. Fixed real Linux TUN in the daemon (`/dev/net/tun`, address/route setup), exact-host OSPF `PeerForIP`, next-hop `SendPacket` from TUN, non-fatal TUN send errors, OSPF management provider, and stale-LSA de-duplication. F50 state: `easytier0` `10.64.0.50/24`, `/root/config/easytier/config.toml` (0600), `/etc/init.d/easytier` enabled, LuCI `admin/vpn/easytier`, `ip rule 8990` to keep the overlay out of sing-box table 2022. Verified peer list, ICMP 3/3 0% loss, CGI JSON, view JS HTTP 200, and reboot auto-start. Evidence: `docs/LUCI_EASYTIER_F50.md`, `GO_REWRITE_SE.md` §11.6.
- **Do not** re-extract the LuCI tarball over a live install without restoring the real config: the tarball carries the template `config.toml` and overwrites `/root/config/easytier/config.toml`. Backups are under `/root/backup/easytier-*`. Plain tar extraction under Windows Git Bash also loses exec bits; `chmod 755 /usr/bin/easytier-* /etc/init.d/easytier /www/cgi-bin/easytier-api` afterwards.
- F50 peer config uses **TCP only** (`tcp://110.40.168.232:11010`); adding the UDP peer caused two sessions (`udp,tcp`) and 100% ICMP loss. sing-box/smartdns were left untouched.
- `go-release.yml` was **not dispatch-verified** because the user forbade commit/push; `actionlint` and YAML parse are clean, and the previous run 35833639733 failure was `actions/download-artifact` after 5 retries, which the new `gh run download` retry loop replaces.
- On Windows `gofmt -l .` flags all untouched CRLF files (`core.autocrlf=true`); verify changed files and the LF index copies instead (see global memory).

### 独立验收（2026-10-20，dispatcher 会话复核）

- **任务 1**：本机复跑 `cd go && go vet ./... && go test ./...` 全绿；18 个改动的 `.go` 转 LF 后 `gofmt -l` 为空；TODOLIST 统计 **46 complete / 17 in-progress**；README 仅剩「100% 的精力」这类非兼容性表述；`go-release.yml` YAML 解析通过、`GO_VERSION=1.25.0`、`gh run download` 重试、placeholder job 已移除；`DEFERRED.md` 只在 release 时由 workflow 生成（repo 内没有属预期）。
- **任务 2**：`100.64.0.2` 复核 PID **248211**、启动时间 `Sat Jun 13 10:10:51 2026` 未变；临时端口 21010/21020/21021/22010/25888/25889/26888 **全部无监听**；`/tmp/easytier-go-interop` 已删；peer 表 = 基线 7 个 + `10.64.0.50 f50`（第 8 个，任务 3 刻意新增）；无 10.64.0.249/.250 残留路由。
- **任务 3**：F50 实测 `easytier0=10.64.0.50/24`、`ip rule 8990` 在、`/etc/init.d/easytier status=running`、`/etc/rc.d/S99easytier` 已 enable、`ping 10.64.0.1` **3/3 0% loss**、CGI JSON 正常、view JS `200 11000`、menu/config.toml(0600)/二进制/CGI 权限齐全、sing-box(5656) 与 smartdns(4437) 仍在跑；`bootcause.log` 有 `2026-10-20 18:32:21 Reboot into normal`，uptime 12min 且服务已自启。
- **观察项（不阻断）**：验收瞬间线上看 f50 为 **26% 丢包 / ~556ms**（5G 波动；F50 侧自测 3/3 0%）；`quic/*/go_to_rust` 4 cell 仍 experimental；`go-release.yml` 未真正 dispatch（需 push）；全部改动未 commit/push。巡检 cron `6e1ed216-...` 已停用。

### 2026-10-21 F50 延迟 1.0ms 修复 + cfst 式 cgroups（v1.0.1）

- 症状：F50 `easytier-cli peer` 所有 peer 都显示 1.0ms。**根因不是 sing-box 劫持**：路由本就直连（`ip route get 110.40.168.232`→`sipa_eth0`，`10.64.0.1`→`easytier0`）。
- 三个 Go bug：①生产代码从未设 `PingerEnabled`（只有测试设）⇒ 无 pinger，`PeerLatencyMS` 恒返回哨兵 `1`；②参考实现 Ping→Pong **不交换 From/To**（`peer_conn.rs` 只翻 packet_type），pong 的 `ToPeerID` 仍是远端，Go 把包当转发送回 ⇒ pinger 收不到；③`removeSession` 无条件删 `pingers[peerID]`，被替换的旧会话退出时会杀掉**新会话**的 pinger，`registerSession` 也不停止被替换的旧 pinger（泄漏）。
- 修复：daemon 开启 pinger；remote-addressed pong 在路由前投递 pinger（本地 pong 仍走原路径供 embedder 观察）；`removeSession` 只停止归属于自己的 pinger；替换会话时停止旧 pinger；未知延迟返回 0，CLI 显示 `-`。
- 结果（F50 v1.0.1，重启后复核）：`qcloud-sh 76.0ms` 真实 RTT；**多跳 peer 显示 `-`**（pinger 按直连会话建立，F50 只有一条 TCP 直连，其余经 OSPF 走 qcloud-sh——显示 `-` 才是诚实的）；线上 `100.64.0.2` 看 f50 = **49.85ms / 0.0% 丢包**（修复前 ~556ms / 26%）；OSPF 链路 cost 改用真实 RTT（`directLinkCosts`），不再被假 1ms 污染。
- cgroups 隔离（按 cfst）：`/sys/fs/cgroup/easytier`；nft `ip easytiermark`（output/mangle）`socket cgroupv2 level 1 "easytier" meta mark set 0x2345`；`ip rule 8998 fwmark 0x2345 lookup main`；`/usr/bin/easytier-cgroup-exec` 写 `cgroup.procs` 后 exec core。init 脚本每次 start 重建；**重启实测**（`2026-10-21 09:08:38 Reboot into normal`）后 cgroup/nft/rule 全部自动恢复、服务自启、ping 0% 丢包。
- 部署注意：F50 是 apk 系统；`scp` 必须加 `-O`（无 `sftp-server`）；覆盖运行中的二进制前先 stop。包已重打为 **1.0.1**（ipk + plain tarball，含 cgroup wrapper）。
- Dashboard（2026-10-21）：Peers 表的「下一跳」改为显示**主机名**（本机/直连显示 `DIRECT`，未知回退 ID）；移除独立的「路由」卡片（该部署所有非直连路由都只经唯一直连 peer 一跳，Peers 表已包含该信息）。
- 高级设置（2026-10-21）：新增「高级设置」卡片，26 个开关全部落地（latency_first / use_smoltcp / enable_ipv6(反) / auto_public_ipv6 / KCP+QUIC proxy+input / disable_p2p / p2p_only / lazy_p2p / bind_device / no_tun / enable_exit_node / relay_all_peer_rpc / need_p2p / multi_thread / proxy_forward_by_system / enable_encryption(反) / TCP+UDP 打洞 / udp 广播中继 / disable_upnp / disable_sym_hole_punching / accept_dns / private_mode）。`get_basic` 返回 `flags` 对象，`save_basic` 写入 `[flags]` 并重启；F50 实测 `disable_upnp` true→false 往返成功。`auto_public_ipv6` 仅存盘，2.6.4 Go 核心无对应 flag。
- 2026-10-21 高级设置两个 bug 已修：①`E()` 的 `checked` 是 HTML 属性，`checked="false"` 仍算选中 ⇒ 改为建元素后设 `.checked` 属性；②`save_basic` 对请求缺失的 flag 用硬编码默认值 ⇒ 旧缓存页面保存会把 `[flags]` 清成默认（曾把 latency_first/multi_thread/private_mode 重置为 false）⇒ 改为**合并**：缺失键保留磁盘现值。已恢复上述三个值为 true。视图改名为 `dashboard_v2.js`（菜单指向 `easytier/dashboard_v2`）以绕开浏览器缓存；headless 渲染测试确认 26 个标签、勾选状态与 `[flags]` 一致；不带 flags 的旧格式保存不再改动现值。
- **Web 控制台接管（2026-10-21，v3）**：`/root/config/easytier/managed.json` + LuCI「Web 控制台接管」卡片。启用后 procd 改为运行**官方 Rust** `/root/software/easytier-official/easytier-core -w <url> --machine-id <id> --hostname <name>`——**只有官方核支持控制台 config-server 协议**，Go 的 `-w` 只心跳/记录配置不应用；本地 TOML 不再传给核心，`save_basic`/`save_config` 直接返回 `local configuration is locked: managed by the web console`，页面所有本地输入禁用。F50 实测：官方核启动并 `Web client started successfully`、`Successfully connected to udp://easytier.wx2020.cn:22020`；机器 `f50` 尚未在云端注册 ⇒ 控制台不下发网络配置，当前 **0 peers（回环到 100.64.0.2 的链路暂时中断）**。关掉开关即回到 easytier-go + 本地配置。视图 `dashboard_v3.js`（菜单 `easytier/dashboard_v3`）。
- 2026-10-21 托管模式 Peers 不可见已修：官方 `easytier-cli -o json peer` 返回**数组**且字段是 `cidr/lat_ms/cost`（p2p/relay(2)/Local），而面板读的是 Go 的 `{"peers":[{id,hostname,ipv4,latency_ms,next_hop,cost}]}` ⇒ `status.peers.peers` 为 undefined。CGI 现按两种形状归一化（只用 jq 内建函数；**F50 的 jq 未编 Oniguruma，不能用 `sub()`/`match()`**）。修复后托管模式显示 8 个 peer：f50(Local) + qcloud-sh(p2p 51ms) + 510s-server/homeserver/liteserver/aws-jp/colocrossing/cloudcone；`ping 10.64.0.1` 3/3、约 52ms、0% 丢包，说明云端注册/下发已成功、链路已恢复。

### 2026-10-21 Web 控制台（config-server）客户端协议：F50 已由 Go 核托管（部分验收未过）

- 新增 `go/internal/webconsole/`（session/console/service/config_map/uuid + 测试），复用 `rpc.PeerRpcManager`：**控制台两端 peer id 都是 1、RPC domain 为空**。
- **⭐ 方法索引是 1-based**（参考生成器 `index = 声明位置 + 1`，0 为 unknown）：`WebServerService.Heartbeat=1`、`GetFeature=2`；`WebClientService` 1..8；`ConfigRpc` 1..2。**0-based 会让每次调用变成静默「无此方法」**，实测参考 2.6.4 客户端就是发 method=2(GetFeature)/1(Heartbeat)。
- **机器 UUID**：`--machine-id` 传 UUID 或任意串（参考实现用 SipHash-1-3 派生）。控制台里 `f50` 的真实 UUID = **`ed618f32-5da5-6dc0-5ceb-7269445226cf`**，用 `ET_CONSOLE_PROBE_ADDR=0.0.0.0:<port> go test ./internal/webconsole -run TestCaptureRealClientHeartbeat -v` 起我们自己的控制台实现、再用官方核 `-w udp://<本机IP>:<port>/wx2020 --machine-id f50` 连过去即可捕获（该测试同时证明**官方 Rust 客户端 ↔ 我们的 Go 控制台实现互通**：隧道/RPC/心跳全通）。
- **daemon `-w` 已接**：`cmd/easytier-core/webconsole_backend.go`（`webconsole.Backend` 实现 + `runWebConsole`），`-w` 时不再加载本地配置、无需 `--listen`；`instance.InstanceManager` 新增 `Remove(name)`。
- **⭐ Noise 数据帧（2026-10-21 定位并修复）**：参考的 secure filter 加密的是**整个内层 ZCPacket（含 16 字节 peer-manager 头）**，外层重新填 `(from=0,to=0,PacketType=Data)` + encrypted 标志；我们原来只加密 payload、沿用原头 ⇒ 官方解出来是裸 RpcPacket、直接丢弃（表现：握手成功但之后所有 RPC 超时）。`internal/webclient` 收发两侧已改为整包加解密 + 接收侧重新解析。
- **实网结果（F50）**：修好后 **Noise 心跳被官方控制台接受**；控制台会主动调 `WebClientService method=8`（ListNetworkInstanceMeta）轮询，并**成功下发 wx2020 配置**：`easytier0` = `10.64.0.50/24`、监听 tcp/11010；`ping 10.64.0.1` ≈60ms、`10.64.0.2` ≈74ms（真实 mesh RTT，不是之前的亚毫秒假象）。
- **⚠️ F50 上走 IPv6**：`udp://easytier.wx2020.cn:22020`（v4）从 5G 侧丢包严重（GetFeature 常年超时），改用 `udp://[2402:4e00:1420:1600:4e34:b51e:ac5a:0]:22020/wx2020` 后稳定；managed.json 已写 IPv6 字面量。
- **心跳改为并发发送**：每秒发一个、各自带超时，连续 10 次失败才断线重连（原来串行等待会因丢一个包卡 20s）。
- **重启自恢复已验**：控制台下发的实例配置缓存在 `<数据目录>/easytier/webconsole/<inst-id>.toml`，启动时 `Backend.Restore` 重放；F50 实测 `reboot` 后服务自启、实例自动恢复、`easytier0=10.64.0.50/24`、`ping 10.64.0.1` **3/3 0% 丢包**（55–409ms，5G 抖动）。daemon 每 30s 打印 `instance ... has N peers: id(ms)`。
- **8 peers 已达到（口径=OSPF 已学到的 peer）**：daemon 日志 `has 1 direct peers, 8 routed peers`；`ping` 实测 `.1/.2/.3/.6/.7/.8/.9` 全 0% 丢包，`.4/.5` 离线 ⇒ 网状是通的。**直连仍只有 1 个**（公共服务器），其余走 OSPF 多跳，未像官方核那样逐 peer 建 p2p 直连。
- **`CollectNetworkInfo` 已填 peer**：`InstanceInfo` 现在返回 `running`/`dev_name` + `Peers` + `PeerRoutePairs`（next hop/cost/path latency/hostname），控制台能看到 8 个 peer。
- **本地配置锁定已验**：托管模式下 CGI `save_config` 返回 `local configuration is locked: managed by the web console`，`get_config`/`status` 正常。
- **控制台下发是服务端自主节奏**：10:55、11:13 各下发过一次；故意清缓存后 2.5 分钟内**没有**再次下发（它只轮询 method=8）。⇒ 重启恢复靠本地缓存，不靠控制台重发。
- **`-race` 在本机怎么跑**（重要，386 Go 默认不支持）：`CGO_ENABLED=1 GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go test -race ./...` —— 用本机 mingw64 的 gcc 交叉成 windows/amd64 的 race 二进制，能在同一台 x64 机器上直接跑。2026-10-21 实测 **44 包全绿、无数据竞争**（并借此修掉 mock 测试里一处计数器无锁读取）。
- **daemon 级 E2E 测试**：`go test ./cmd/easytier-core -run TestRunWebConsoleDrivesInstances` 起真实 `-w` daemon + 进程内控制台（UDP 隧道），把 WebClientService 8 个方法 + ConfigRpc 的 Patch/Get 全部打通并验证实例真实创建/删除；`internal/webconsole` 增加了导出的 `Serve(ctx, channel, services...)` 供控制台侧使用。
- **⭐⭐ p2p 直连已修好（2026-10-21，之前只有 1 个直连 peer）**：三处**叠加**的线级不匹配，缺一不可 —— ①**方法索引 1-based**（`DirectConnectorRpc` GetIpList=1/Punch=2、`UdpHolePunchRpc` 1..5、`TcpHolePunchRpc` ExchangeMappedAddr=1，我们原先全是 0-based）；②**descriptor 的 proto_name 必须等于服务名**（参考注册表按 (domain, service_name, proto_name) 查，我们发的是占位符 `"EasyTier"` ⇒ 新增 `rpc.PeerRpcManager.CallService`）；③**peer_rpc 的 body 是 protobuf 不是 JSON**（参考用生成的 `call` 而非 `json_call_method`，我们原先用 protojson ⇒ 对端回 `prost_decode_error:{}`）。**排障阶梯**：完全没有出站拨号（RPC 先失败）→ `prost_decode_error`（服务找到了、体编码错）→ 直连建立。F50 实测：**7 个直连 peer**（原 1 个），面板有每 peer 延迟，`ping 10.64.0.1` 均值 119ms→70ms，`10.64.0.9` 从 100% 丢包变 ~200ms 可达。防回归测试：`directconn/wire_identity_test.go`、`rpc/call_service_test.go`、`punch/method_index_test.go`、`tcphole/method_index_test.go`。
- **⭐⭐ 控制台机器页整表空白的真因（2026-10-22）：前端模板硬解引用 `route.feature_flag.is_public_server`**（`easytier-web/frontend-lib/src/components/Status.vue`，只有这一处没用可选链）⇒ 我们没填 `feature_flag` ⇒ 浏览器抛错 ⇒ **整张表渲染不出来、节点数 0**。修法：每条 route 都带一个空 `feature_flag`。（`easytier-web/` 是 **Rust 后端 + Vue 前端**，是本仓库内的控制台实现，可直接当参考读。）
- **⭐ ping/pong 匹配错位（2026-10-22 修）**：ping 会被**路径上的其它节点代答**，且参考回 pong **不交换 header**（to 仍是被 ping 者）⇒ 按 FromPeerID 分发会把 pong 交给错误的 pinger ⇒ 表现为**恒定 50% 丢包 + 延迟失真**。修法：ping 的 seq 改为**节点内全局唯一**，pong 按「谁在等这个 seq」分发。
- **⭐ 控制台机器页的 peer 表曾全是 NaN/空（2026-10-21 修）**：控制台按参考的 `CollectNetworkInfo` 结构渲染（`my_node_info` / `routes` / `peers[].conns` / `peer_route_pairs`），我们之前只报 peer_id ⇒ 列全空、延迟 NaN。现已按参考填满：虚拟 IPv4、主机名、版本、下一跳、代价、路径延迟、连接类型(p2p/relay)、往返时延、丢包率、每连接 rx/tx 字节与包数（`PeerSession` 新增 TrafficStats 计数）。**控制台只在打开机器详情页时才拉 method=3**（平时只轮询 method=8），所以改完要刷新页面才看得到。
- **⭐ 面板延迟与 ping 差很大的三个原因（2026-10-21 已修）**：①**控制包不加密**——参考 `should_skip_encrypt` 跳过 Ping/Pong（收发两侧都跳），我们把 ping 也加密 ⇒ 官方 peer 丢弃我们的 ping ⇒ pinger 连丢 5 次自杀 ⇒ 面板数字**冻结**在最后一次测量；②参考"**连丢 5 次 ping 就断开该 peer 连接**"，我们只停 pinger 留死会话 ⇒ 窗口永不刷新（新增 `PeerConnectionManager.ClosePeer`）；③参考**固定 1s ping + 15 样本窗口**（`WindowLatency::new(15)`），我们 100 样本 + 指数退避（最多 32 倍）⇒ 数字滞后近一分钟。另外**ping 会被路径上的节点代答**（实测：发给 qcloud-sh 的 ping 由 peer 1666128361 回），所以参考对中继 peer 报的是**路径延迟**、对直连 peer 才报自身 RTT（我们已按此改：`pathLatencyMS`）。状态文件现在带 `loss_rate`/`latency_samples` 两个诊断字段。
- **⚠️ 「下一跳全是 qcloud-sh」的原因与后续（2026-10-21）**：面板的"下一跳/代价"来自 OSPF 路由表。参考实现**按跳数计代价**（`calculate_cost` 对已直连的一对返回 1），延迟放在独立字段 `path_latency`；我们却把**毫秒延迟**当作边代价通告 ⇒ 直连边（194ms）比 2 跳中继（1+1）还贵 ⇒ 路由继续走中继，面板如实显示"下一跳 qcloud-sh"。改成按跳数后路由表正确（next hop = 该 peer、cost 1），**但会暴露下一个缺陷：直连会话目前只通控制面**（pinger 有延迟、TUN 数据包不落地）⇒ 那样 6 个 peer 的 overlay IP 会变成 100% 丢包。**因此代价单位暂时保留延迟口径**（`nodeRuntime.directLinkCosts` 注释已写明），待直连数据面修好再切。
- **⭐ 远端 proxy_cidr 内核路由已补（2026-10-21，官方核有/Go 核原先没有的功能缺口）**：`core.ProxyRouteManager` 按 OSPF 通告（排除本机）diff 安装/撤除 `ip route <cidr> dev easytier0`，实例每 10s 轮询、Close 时清理、失败的安装下次重试。F50 实测：`192.168.5.0/24`、`192.168.100.0/24` 已装上，且**从 F50 经 mesh 拿到 192.168.100.11:22 的 SSH banner**（该主机禁 ping 属正常）⇒ 官方核提供的子网可达性已等价恢复。
- **LuCI 面板托管模式显示 8 peers（2026-10-21 修）**：Go 核 `-w` 模式没有 RPC portal，`easytier-cli` 看不到；daemon 现在把 peer 表写进 `ET_CONSOLE_STATUS_FILE`（默认 `<tmpdir>/easytier-console-status.json`，30s 刷新，JSON 内带 `updated` 时间戳——**busybox 没有 stat(1)**），CGI 在 easytier-cli 无 peer 时回退读它。F50 实测面板 peer_count=8，主机名与官方核一致。init 已注入 `ET_CONSOLE_STATUS_FILE=/root/config/easytier/console-status.json`。
- **运维坑**：手工测试残留的旧进程会占住 11010/15888，导致新实例起不来 —— 清理时必须用**精确 PID**（`ps w | grep "easytier-core -w"`），不要 `pkill -f`。
- 部署入口：`managed.json` 增 `"core": "go"`（默认）/`"official"`，init 按此选二进制，官方核保留为回退；改 `core` 后 `/etc/init.d/easytier restart` 即可。

### 2026-10-21 家宽短断导致 sing-box TUN 卡死（透明代理全断）

- **触发**：10:24 左右家宽短暂掉线——`home.wx2020.cn`（`27.200.0.115` / IPv6）443 全超时，而 `derp-ta.wx2020.cn` CNAME 到它；tailscale 的 DERP 与 `wx-nas` 的 `192.168.100.0/24` 子网路由都在家宽侧。F50 自身 WAN 正常（223.5.5.5、qcloud、headscale 都通）。
- **现象**：透明代理（TUN）全断、Google 超时；但 `mixed-in 10809` 显式代理正常（204），CN 直连正常；`ip rule` / table 2022 都还在。
- **证据**：clash `/connections` 里 3 条 `10:24:00`/`10:24:56` 的 `ts-ep` 连接（`192.168.100.11:22`、`192.168.100.1:80`、`192.168.5.100:11012`）0 字节挂着；`inbound/tun` 日志停在 `10:25:23`；`sbtun` TX dropped 8746→11838，而 TX packets 停在 118830 不涨（内核队列满）。
- **根因链**：`ip_cidr [100.64.0.0/10, 192.168.5.0/24, 192.168.100.0/24] → ts-ep` 是**静态**规则，不检查 tailscale 路由是否存在；tailscale endpoint 的 dial 无超时；挂起的 dial 占住单队列 gVisor TUN 的读循环，内核 TX 队列（qlen 500）满后新连接（含 Google）进不了 TUN。
- **修复**：`/etc/init.d/sing-box restart`（新 PID 20645）后透明 Google 恢复 **204**，Windows 侧透明/显式也都是 204；`inbound/tun` 日志与 `sbtun` 计数恢复。更轻的尝试是 `curl -X DELETE http://127.0.0.1:7890/connections`（本次未先试）。重启时家宽也恢复，`ping 192.168.100.1` 2/2（23–71ms）。
- **教训**：静态 overlay 路由 + 无 dial 超时 + 单 TUN 队列会互相放大；上游不可达时应撤规则或让流量快速失败，别让死 overlay 的 dial 堵住整个 TUN。家宽是 DERP + 两个 subnet router 的单点，真要冗余需把 DERP/subnet router 放到第二站点。
- **DERP map / 端口（10:52–11:05 复核）**：`tailscale debug derp-map` 显示 4 个 region——`shq`(901, `derp-sh.wx2020.cn:443`, STUN 3478, qcloud `110.40.168.232`)、`tac`(902, `derp-ta.wx2020.cn:5001`, STUN 3479, home `27.200.0.115`)、`tyo`(`derp-jp.wx2020.fun:443`)、`sfo`(`derp-usa.wx2020.fun:443`)。**`derp-ta` 的 DERP 端口是 5001，不是 443/80**（443/80 超时属正常，别据此判定家宽 DERP 挂）。
- **F50 实测（3 次）**：`ta:5001` v4 TCP connect 1.9–2.6ms 是 TUN 本地握手、不是真实 RTT；以 TLS 为准 v4 **117–135ms**、v6 **113–122ms**。`sh:443` v4 connect 50–51ms/TLS **133–159ms**；v6 connect **26–30ms**/TLS **89ms**（最好），但 qcloud 偶发 1.0–1.5s 级 connect/TLS 抖动。ICMP：ta v4 47ms/0%、v6 59ms/25%；sh v4 67ms/25%、v6 36ms/25%。⇒ **v4 上 home 略优（ICMP/TLS 都更低），v6 上 qcloud 更优（connect/ICMP 更低），不是“v4/v6 都弱”**。
- **当前选择**：重启后 F50 的 sing-box 只有到 qcloud `110.40.168.232:443` 的 v4/v6 连接，**没有**到 home `27.200.0.115:5001` 的连接 ⇒ 现在用 `shq`；日志里的 `derp-ta` DNS 只是 netcheck 探测。之前确实用 `tac`（家宽侧延迟低），选择随网络变化。tailscale 只维护一个 home DERP、不并行；本次 home DERP 挂掉后 F50 未自动切 `shq`，重启才恢复。`qcloud.wx2020.cn` 不是 DERP 主机名，DERP 是 `derp-sh.wx2020.cn`。
- **选择逻辑（源码 `net/netcheck/netcheck.go`）**：netcheck 用 **STUN（v4/v6）测每个 region 的 STUNPort**（`tac` 3479 / `shq` 3478），UDP 全失败才走 HTTPS `/derp/latency-check`；full report 每 **5min**，增量只测最快 3 个 + 当前 home（home 4 次重试）；每个 region 取近 5min `bestRecent` 最低值；**切换粘滞**：新 region 要比当前快 **>10ms 且 >33%** 才切，否则保留当前（还考虑 keepalive/ForcePreferredDERP/RegionScore）。peer 之间用 **peer 的 home DERP**，不是本机 home。⇒ 我上面用 ICMP/TCP 测的延迟不是 DERP 选路的输入，实际看 STUN；这也解释了“只走 home”可能是粘滞/STUN 更快，而不是 TCP 443 更好。
- **2026-10-21 11:15 已改 F50 `sing-box.json`**：`route_exclude_address` 里的 `27.200.0.60/32` 替换为 `27.200.0.0/23`（备份 `sing-box.json.bak-20261021-111436`）。`sing-box check` 通过，重启后新 PID **16089**；table 2022 不再有 `27.200.0/1` 段，`ip route get 27.200.0.115` → `dev sipa_eth0 src 10.137.12.146`（不再走 sbtun）；`curl -4 https://derp-ta.wx2020.cn:5001/` 200（connect 44ms/TLS 175ms），tailscale 已建立到 `2408:8214:...:5001` 的 derp-ta 连接（IPv6），qcloud 443 连接仍在（control/shq）；透明 Google 仍 204。⚠️ 若 LuCI sing-box 应用重写配置，需在应用的 route exclude 字段里重新加 `27.200.0.0/23`；仓库 `sing-box-config/client/zte-f50.json` 尚未同步（仍是 `27.200.0.60/32`）。
- **不要把 5001 连接当成 F50 的 home DERP（11:20 `tailscale debug netmap`）**：控制面记录 **`zte-f50.HomeDERP=901`（shq/qcloud）**，不是 902；`wx-nas`/`qcloud-sh`/`headplane` 也是 901。`homeserver`/`debian` 的 HomeDERP=902（tac），`aws-jp`=911，`liteserver-nl`/`colocrossing`/`cloudcone`=912。F50 到 `2408:8214...:5001` 的连接是**为 902 的 peer 做 relay**（homeserver/debian），不是它自己的 home；netstat 看到 5001 只说明在给 902 peer 中继。F50 自己的 home 仍是 901，改 `27.200.0.0/23` 只是让到 902 的 relay 走直连。
- **⚠️ Go 核托管模式不装远端 proxy 路由（13:47 实测 + 代码确认）**：`easytier0` 已起（10.64.0.50/24、8 routed peers），但 main 表**只有** `10.64.0.0/24`，没有官方核之前装的 `192.168.100.0/24`、`192.168.5.0/24`。代码里 `PlanRoutes/CleanupRoutes` 只用于接口清理，**没有任何"远端 peer proxy_cidr → 内核路由"的路径** ⇒ 官方核有、Go 核没有的功能缺口。影响：F50 上 EasyTier 侧目前宣告什么都不装，"ts /24 + et /25"之类的分流方案在 F50 上零效果，除非先补这个缺口（或换回官方核）。
- **"ts 宣告 /24 + et 宣告 /25" 能否解决冲突——不能，两层原因**：①**跨表 LPM 不成立**：Linux 双栈节点 tailscaled 的 `ip rule 5270 → table 52` 先于 main，table 52 的 /24 匹配整个 /24，main 里的 /25 永远轮不到；只当 tailscale 撤销时 /25 才兜底——即 failover 覆盖从现状（两边都 /24 = 全量兜底）**砍半**，是退化。②**F50 上零效果**：静态 `ip_cidr /24 → ts-ep` 顺序匹配、不看 main 表，且 Go 核不装远端路由；要让 /25 生效必须再加 `route_exclude_address`/`ip rule 8990`。该方案唯一价值是"F50 确定性分流（半边 EasyTier）"，需三处配套（控制台 /25 + F50 排除 + Go 核补路由安装），并接受 Linux 侧 failover 减半、EasyTier-only 节点只剩半边。更干净：单一归属（一侧完全不宣告）或 /32 钉主机。
- **当前 EasyTier 状态（10:44）**：`/root/config/easytier/managed.json` 已改为 `{"enabled":true,"core":"go","url":"udp://easytier.wx2020.cn:22020/wx2020","machine_id":"ed618f32-...","hostname":"f50"}`，进程是 `/usr/bin/easytier-core -w tcp://easytier.wx2020.cn:22020/wx2020`（**Go 核**，仅心跳/控制台），main 表里**没有** `10.64.0.0/24`、`192.168.100.0/24`、`192.168.5.0/24` 路由；Go 的 `-w` 不做配置下发，要恢复 overlay 需官方核 managed 或本地配置（非 `-w`）。`ip rule 8990 to 10.64.0.0/24` 由 init 脚本重新加回，但无路由时无实际作用。

### 2026-10-27 复核（无新代码改动）

- 最后一次代码改动停在 **2026-10-22 17:09**（SE.md §11.7 + pinger/connection_manager/webconsole_backend/tmpdecode）；此后至 10-27 无新提交、无新文件。
- 本机复核：`go build ./...`、`go vet ./...` 全绿；全量 `go test ./...` 中 `quicwire` 的 `TestQUICWireHandshakeAndStreaming` **偶发 `client ReadFull failed: EOF`**（仅在全量并行负载下出现，单独 `-run TestQUICWireHandshakeAndStreaming -count=1` 重跑通过）⇒ 时序抖动，非回归；如 CI 再撞可考虑加重试或降低该测试并发敏感度。

### 2026-10-27 控制台详情拉不到（f50 看得到但无节点）——RPC 响应缺分片，已修复并部署

- **症状**：线上控制台能看到 f50 机器，但机器详情页空白；F50 daemon 日志每次 `method=4`（CollectNetworkInfo，8-9 peer ≈2.7KB）后紧跟 `session ended: UDP peer packet exceeds EasyTier limit: 2756` + `reconnecting in 30s` 循环。method=8（26 字节）一直正常 ⇒ 「看得到、看不全」。
- **根因**：`go/internal/rpc/peer_rpc.go` 的 `sendResponse` 硬编码 `TotalPieces: 1`——请求有 `sendFragmented`（1300B/片，对齐参考 `RPC_PACKET_CONTENT_MTU`），**响应没有**；超 Go UDP 传输层 2000B 上限即撕会话。参考端 `build_rpc_packet → split_rpc_content_for_udp_budget` 对请求/响应统一分片。
- **修复**：`sendResponse` 改为把 `RpcResponse` 信封交给 `sendFragmented(..., isRequest=false)`；小响应保持单片兼容形态。防回归测试 `rpc/response_fragment_test.go`（~10KB 必分片且重组逐字节一致；小响应单片带 descriptor）。
- **部署**（F50，`/usr/bin/easytier-core` v1.0.1 位置，最终 md5 `2013d81d…`）：交叉编译 arm64 静态 ELF → `stop` → 备份 `/root/backup/easytier-core.bak-20261027-pre-respfrag` → scp `-O` 替换 → `start`。**实测**：method=4 每 ~7s 被控制台轮询、`peers=8 routes=8`、零断连；`ping 10.64.0.1` 3/3；qcloud-sh `easytier-cli peer` 显示 `f50 10.64.0.50/24 p2p 50ms 0.0% v2.6.4-gorespfrag1`。迁移记录 **SE.md §11.8**。本机 build/vet/test（含 `-race`）全绿；改动仍**未 commit**。
  - **⚠️ 手工交叉编译必须注入版本号**：`-ldflags "-s -w -buildid= -X main.version=v2.6.4-<标记> -X main.commit=$(git rev-parse --short=8 HEAD)"`，否则 `main.go:38` 默认 `0.0.0-dev` 上线、控制台版本列显示 0.0.0-dev（10-27 首次部署就漏了，已重打为 `v2.6.4-gorespfrag1`）。

### 2026-10-27 mesh「只有少量 p2p」定案：会话层 8 条直连都在，路由层刻意/结构性全走中继

- **现象澄清**：f50 daemon 自报 `has 8 direct peers`（`manager.Peers()` 会话层 8 条直连会话，qcloud 的 `easytier-cli peer` 也显示 8 peer 全 p2p）；但 f50 的路由表/**控制台详情**把 7 个 peer 的 next_hop 都指向 qcloud-sh（cost=2）⇒ 控制台把它们标成 relay。**「p2p 少」是路由口径，不是会话没建立**。
- **原因 a（Go 侧 OSPF 代价语义不对称，结构性缺陷）**：`directLinkCosts` 给自己 LSA 的直连边标**延迟毫秒**（41–275），但线上传输时代价不随包走、接收端 `advertisementsFromSyncRequest` 一律重建为 **Cost: 1**（对齐参考协议 unweighted 语义）。SPF 里经中继 2 跳=2 恒小于任何直连边（41+）⇒ 路由永远选中继。**即使数据面是好的，这个不对称也会让 Go 节点避开直连**。
- **原因 b（直连数据面未通，刻意保留延迟口径）**：~~直连会话目前只通控制面~~ **10-27 下午已修正此判断**：Go↔Go 直连数据面 E2E 是通的（`direct_data_plane_test.go`），真正的断点是 **Go→Rust 的 noise 加密 Data 帧**（见 10-27 会话级 pong 条目）。
- **顺带发现（小缺口）**：f50 未出现在 peer-center global peer map 的上报源里（qcloud `easytier-cli peer-center` 没有 f50 行，别的节点只有 qcloud 把 f50 列为直连）⇒ 其它节点无法把 f50 当打洞候选。`reportJob` 每 5s 跑、`ListDirectPeers` 有实现，需查上报为何没到中心节点。
- 实测对照（f50，1200B 大包 ping 全部经中继转发）：`.1`=63ms、`.3`=82ms、`.7`=231ms、`.40`=273ms，全通 0 丢包 ⇒ 中继路径数据面正常。

### 2026-10-27 直连数据面 E2E 已证通；切跳数代价上线即暴露「半开 UDP 打洞会话」，已回滚保连通

- **直连数据面结论修正（重要）**：10-21「直连会话只通控制面」的判断**已被推翻**——新增 `core/direct_data_plane_test.go` 端到端证明 TUN 帧 → 直连会话（Noise 加密 Data 包）→ 对端协议栈全通（Go↔Go）。此前全走中继的真正原因只是**代价语义不对称**（自己 LSA 延迟口径 vs 线上统一 cost=1）。
- **跳数代价切换 + 线上 A/B（已回滚）**：`directLinkCosts` 改为每边 cost=1（`v2.6.4-gomesh2`）部署 F50 后，f50 路由表变 DIRECT/cost=1，部分 peer 数据面真实走直连（.1/.6/.40 通），**但 .2/.3/.7/.9 100% 丢包**（此前中继模式全通）。
- **暴露的新缺陷：半开 UDP 打洞会话**。f50 的 directconn 打洞「established」是**单方面**记录——`/proc/net/udp` 实测只有 qcloud(TCP)+aws-jp(UDP, 52.198.175.31:1443) 两条真实远端 socket，其余 peer 的"直连会话"对端 socket 已消失。f50 往死会话发 Data 丢在 NAT 外。
- **为什么 pinger 没杀掉死会话**：ping 从死 UDP 会话发出后，**pong 被路径上的中继节点代答**并按 seq 分发成功（qcloud loss=50% 即代答证据）⇒ 连丢 5 次的自杀条件永不触发。参考实现同样有代答，但参考的 ping 选择路由发送且 disconnect 判定同样会被代答干扰——此差异需单独修（思路：pinger 要求 pong 从**同一会话**回来才算 RTT 样本，代答 pong 只记 path latency 不抵消连丢计数）。
- **生产状态**：F50 已回滚到 `v2.6.4-gorespfrag1`（延迟口径 + respfrag 修复，md5 `2013d81d…`），8 peer 全通，控制台正常。**cost=1 代码与数据面测试保留在仓库**（含 `-race` 全绿），重新上线的前置条件：①修掉半开会话（pinger 会话级验证）；②对端 socket 存活校验。
- 教训：**线上切路由策略前必须先验证每条直连会话是双向活的**（本次 A/B 恰好是安全的：生产是 overlay ping，回滚窗口 5 分钟）。

### 2026-10-27 会话级 pong 验证落地 + 两次线上 A/B：确认 Go→Rust noise 会话的 **Data 包**不兼容（控制面通、数据面断），生产已回滚

- **修复 1（会话级 pong）已实现**：`deliverPong(packet, fromSession)` 只把「从被 ping peer 自己会话到达」的 pong 交给 pinger；中继代答的 pong 被忽略（debug 日志）。防回归测试 `peer/pong_session_test.go`（同会话完成 RTT；经 session 9 的代答 pong 不完成、ping 超时）。`HasPinger` 导出用于区分「pinger 关闭」与「无样本」。
- **修复 2（边活性过滤）已实现**：`directLinkCosts` 只通告「HasPinger 且 Samples>0」的直连边（pinger 关闭时退回旧语义，保嵌入方兼容）。首版无脑过滤 Samples==0 导致 OSPF 不收敛（测试节点 pinger 关闭 ⇒ 零边），正是测试抓住的。
- **线上 A/B（gomesh3/gomesh4，均回滚）**：cost=1 + 边活性过滤后，f50 路由表 DIRECT/cost=1 的 peer **pinger 有样本（pong 同会话回）但 TUN ICMP 仍 100% 丢**；cost=2 的 .40（死会话走中继）反而通。⇒ **控制面（Ping/Pong，不加密）双向通 ≠ 数据面（Data，noise 加密）通**。Go↔Go E2E 通过、Go→Rust Data 断 ⇒ **Go↔Rust 的 noise 加密 Data 帧不兼容**（Go↔Go 同语义自洽所以测试绿）。interop 的 `tcp/noise_xx go_to_rust` Data 交换 cell 在本机因 oracle 启动参数问题没跑成，正是此缺口。
- **生产状态**：F50 = `gorespfrag1`（延迟口径），**8 peer 全通**。gomesh4 代码（pong 会话验证 + 边活性过滤 + cost=1 + ListRoutes 修复）保留在仓库且测试全绿。
- **cost=1 重上线的唯一前置改为**：修 Go↔Rust noise Data 帧兼容——对照参考 `peer_conn.rs` 的 secure 数据帧（nonce/counter 起始、AAD、header 加密范围）逐字节核对 Go 的 `secure_datagram.go`，补 interop golden 或修 oracle 起参后跑通 `tcp/noise_xx go_to_rust` Data cell。
- 经验：**「pinger 有样本」只能证明控制面同会话双向活，不能证明加密数据面兼容**——两类面要分别验证。

## Maintenance
- 每次改完代码或完成新的分析后，必须调用 `memory-update` skill 检查并更新本文件。
- 发现本文件与代码不符时，以代码为准同步修正。
