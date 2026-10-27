# LuCI App + F50 Deployment — `luci-app-easytier`

Date: 2026-10-20
Target: ZTE F50 / OpenWrt 25.12.5 (MU300), kernel 6.18.57, aarch64
Device: `192.168.0.1`, `ssh root@192.168.0.1` (key auth)

## Why plain files, not `opkg install`

The F50 runs **apk-tools 3.0.5** and has no `opkg` (verified:
`/usr/bin/apk` exists, `opkg` does not). A standard `.ipk` cannot be installed
there, so the app is deployed as plain files, the same way the reference
`luci-app-singbox` was deployed. The `.ipk` is still produced for standard
OpenWrt/opkg systems.

## Build

```bash
cd luci-app-easytier
./build.sh
```

Outputs:

| Artifact | Path |
| --- | --- |
| IPK (opkg systems) | `luci-app-easytier/bin/luci-app-easytier_1.0.0-1_aarch64_generic.ipk` |
| Plain-file payload | `luci-app-easytier/bin/luci-app-easytier-files-1.0.0.tar.gz` |
| Core / CLI | `luci-app-easytier/bin/easytier-core`, `easytier-cli` |

The binaries are `CGO_ENABLED=0 GOOS=linux GOARCH=arm64`, statically linked.

## Deployed layout

| Path | Contents |
| --- | --- |
| `/usr/bin/easytier-core` | Go core, `v1.0.0` |
| `/usr/bin/easytier-cli` | Go CLI |
| `/etc/init.d/easytier` | procd service (`START=99`, autostart enabled) |
| `/root/config/easytier/config.toml` | mode 600, network `wx2020`, overlay `10.64.0.50/24` |
| `/usr/share/luci/menu.d/luci-app-easytier.json` | `admin/vpn/easytier`, title “EasyTier 组网” |
| `/www/cgi-bin/easytier-api` | shell CGI backend |
| `/www/luci-static/resources/view/easytier/dashboard_v2.js` | LuCI view (`v2` is a cache-busting rename; the menu points here) |

The config uses `tcp://110.40.168.232:11010` as the peer. Only TCP is used on
the F50: a first attempt with both TCP and UDP peers left the peer with two
sessions (`udp,tcp`) and ~100% ICMP loss; removing the UDP peer made the
overlay stable.

## Coexistence with sing-box policy routing

The F50 already runs sing-box with `sbtun` and policy table 2022. The main
table has the `10.64.0.0/24 dev easytier0` route, but the sing-box rule
`9001: from all lookup 2022` would capture it. The init script adds a
higher-priority rule before starting the core:

```sh
ip rule add to 10.64.0.0/24 lookup main priority 8990
```

and removes it in `stop_service`. No sing-box/smartdns config or process was
touched. After the rule:

```text
8990: from all to 10.64.0.0/24 lookup main
# ip route get 10.64.0.1
10.64.0.1 dev easytier0 src 10.64.0.50
```

## Verification (final state)

```text
# /etc/init.d/easytier status
running
# ls -l /etc/rc.d/S99easytier
S99easytier -> ../init.d/easytier
# ip -4 addr show easytier0
inet 10.64.0.50/24 brd 10.64.0.255 scope global easytier0
# /usr/bin/easytier-cli peer
1155147577 qcloud-sh        10.64.0.1/24 2.6.4-8428a89d 1.0 1155147577 1
... (all network peers, f50 local 10.64.0.50/24)
# ping -c 3 10.64.0.1
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 99.959/105.552/116.707 ms
```

A final reinstall of the latest `v1.0.0` binary was performed after the
snapshot above; the service restarted and the same peer/ping checks passed
(3/3, 0% loss). The `.tmp/f50/final.txt` snapshot comes from the immediately
preceding binary and is retained for the reboot record.

CGI:

```json
{
  "running": true,
  "version": "v1.0.0",
  "network_name": "wx2020",
  "ipv4": "10.64.0.50/24",
  "peers": 8,
  "routes": 7,
  "rx_bytes": "420",
  "tx_bytes": "876",
  "autostart": true
}
```

`curl -s -o /dev/null -w '%{http_code} %{size_download}'` on
`http://127.0.0.1/luci-static/resources/view/easytier/dashboard.js` returned
`200 11000`. The LuCI page itself requires login; an unauthenticated request
to `/cgi-bin/luci/admin/vpn/easytier` returns `403`, which is the expected
auth gate, not a missing view.

`save_basic` was exercised with the current values and a blank secret
(“keep existing”): it validated the generated TOML with
`easytier-core --check-config`, rewrote the config, restarted the service,
and the peer/ping check passed afterwards.

## Reboot test

Before reboot: `up 5:47`, service PID 23758, 8 peer rows, sing-box PID 4146,
smartdns PID 11596. Rebooted with `reboot` (no br-lan capture; no `timeout`
or `nohup` used). SSH returned after 65 s.

After reboot:

```text
18:33:40 up 1 min
bootcause.log: 2026-10-20 18:32:21 | bootcause="Reboot into normal"
/etc/init.d/easytier status: running
pidof easytier-core: 8385
easytier0: inet 10.64.0.50/24
ip rule: 8990: from all to 10.64.0.0/24 lookup main
peer: qcloud-sh + all network peers + f50
ping -c 3 10.64.0.1: 3/3, 0% loss
CGI status: running, peers 8
sing-box: 5656 (running)
smartdns: 4437 (running)
```

The `bootcause` line is the expected “Reboot into normal” record for the
operator-initiated reboot; no UVLO/power-loss line was added.

## Latency: why the table showed 1.0 ms for every peer (fixed in v1.0.1)

Routing was never the problem: `ip route get 110.40.168.232` already returned
`sipa_eth0` and `ip route get 10.64.0.1` returned `easytier0` (both direct, no
`sbtun`). The 1.0 ms was produced by the Go daemon itself:

1. `PeerConnectionManagerConfig.PingerEnabled` was only set in tests. In
   production no pinger existed, and `PeerLatencyMS` returned the hardcoded
   unknown sentinel `1` for every peer.
2. The reference echoes a Ping as a Pong **without swapping the header**
   (`peer_conn.rs` just flips `packet_type`), so the reply still carries
   `ToPeerID=remote`. Go routed it through the route table (back to the
   sender) instead of handing it to the pinger.
3. Session replacement tore down the wrong pinger: `removeSession` deleted
   `pingers[peerID]` even when the closing session was an older one that had
   already been replaced. `registerSession` also leaked the replaced pinger.

Fixes: enable pingers for the daemon, feed reference-style pongs (remote
`ToPeerID`) to the pinger before routing, only stop the pinger owned by the
current session, stop the old pinger on replacement, return `0` for unknown
and render `-` in the CLI.

Result after deployment and reboot: `easytier-cli peer` shows
`qcloud-sh 76.0 ms` (real RTT) and `-` for multi-hop peers; the live node at
`100.64.0.2` sees `f50 p2p 49.85 ms 0.0% loss` (before: ~556 ms / 26%).
Only directly connected peers can have an RTT sample — every other peer is
reached via OSPF through `qcloud-sh`, so `-` is the honest value. OSPF link
costs also use the measured RTT now (`directLinkCosts`), so the fake 1 ms no
longer skews path selection.

## cgroup isolation (cfst-style)

Even though the route was already direct, the core now gets the same
isolation as `cfst` so a future sing-box rule change cannot capture it:

| Piece | Value |
| --- | --- |
| cgroup v2 | `/sys/fs/cgroup/easytier` |
| nft table | `ip easytiermark`, output/mangle: `socket cgroupv2 level 1 "easytier" meta mark set 0x2345` |
| policy rule | `8998: from all fwmark 0x2345 lookup main` |
| launcher | `/usr/bin/easytier-cgroup-exec` writes its PID to `cgroup.procs` then `exec`s the core |

The init script recreates the cgroup, nft table and rule on every start; after
a reboot the cgroup again contains the core PID, `nft list table ip
easytiermark` and rule 8998 are present, and `ip route get 110.40.168.232
mark 0x2345` returns `sipa_eth0`.

## Dashboard

- The peer table renders the next hop as its **hostname** (`qcloud-sh`)
  instead of the numeric peer ID; direct peers and the local node show
  `DIRECT`. Unknown next hops fall back to the raw ID.
- The separate route card was removed. In this deployment every non-direct
  route is a single OSPF hop through the only direct peer, so the peer table
  already carries the routing information and a second table only duplicated
  it.

## Advanced settings

The dashboard (view `easytier/dashboard_v2`, a cache-busting rename) now has a **高级设置** card with the full flag set. `get_basic`
returns them as a `flags` object and `save_basic` writes each one into
`[flags]` of `config.toml` (then restarts the service). UI -> TOML mapping:

| UI | TOML key |
| --- | --- |
| 开启延迟优先模式 | `latency_first` |
| 使用用户态协议栈 | `use_smoltcp` |
| 禁用 IPv6 | `enable_ipv6` (inverted) |
| 自动获取公网 IPv6 | `auto_public_ipv6` (stored only; 2.6.4 Go core has no such flag) |
| 启用/禁用 KCP 代理/输入 | `enable_kcp_proxy`, `disable_kcp_input` |
| 启用/禁用 QUIC 代理/输入 | `enable_quic_proxy`, `disable_quic_input` |
| 禁用 P2P / 仅 P2P / 延迟 P2P | `disable_p2p`, `p2p_only`, `lazy_p2p` |
| 仅使用物理网卡 | `bind_device` |
| 无 TUN 模式 | `no_tun` |
| 启用出口节点 | `enable_exit_node` |
| 转发 RPC 包 | `relay_all_peer_rpc` |
| 需要 P2P | `need_p2p` |
| 启用多线程 | `multi_thread` |
| 系统转发 | `proxy_forward_by_system` |
| 禁用加密 | `enable_encryption` (inverted) |
| 禁用 TCP/UDP 打洞 | `disable_tcp_hole_punching`, `disable_udp_hole_punching` |
| UDP 广播中继 | `enable_udp_broadcast_relay` |
| 禁用 UPnP | `disable_upnp` |
| 禁用对称 NAT 打洞 | `disable_sym_hole_punching` |
| 启用魔法 DNS | `accept_dns` |
| 启用私有模式 | `private_mode` |

Round-trip verified on the F50: `save_basic` with `disable_upnp=true` wrote the
key, restarted the service, the peer link came back at 44 ms, and saving
`false` restored the original file.

`save_basic` is a **merge**: any flag missing from the request keeps the value
already on disk. This matters because a browser can still hold an older
`dashboard.js` whose payload has no `flags` object; before the merge a stale
client reset the whole `[flags]` block to defaults. The checkboxes also set the
DOM `checked` property (not the attribute) — `checked="false"` is still a
checked box in HTML, which made an earlier build show every option selected.

## Web console takeover (managed mode)

The dashboard has a **Web 控制台接管** card. It stores
`/root/config/easytier/managed.json`:

```json
{"enabled": true, "url": "udp://easytier.wx2020.cn:22020/wx2020",
 "machine_id": "f50", "hostname": "f50"}
```

- `enabled=true` switches the procd command to the **official**
  `easytier-core` at `/root/software/easytier-official/easytier-core` with
  `-w <url> --machine-id <id> --hostname <name>`. That binary is the only
  implementation that speaks the web console's config-server protocol; the Go
  core's `-w` only heartbeats and logs updates.
- Managed mode locks the whole local editor: the view disables every input and
  the save buttons, and the CGI rejects `save_basic` / `save_config` with
  `local configuration is locked: managed by the web console`.
- The local TOML is not passed to the core in this mode, so it has no effect.
- Revert by clearing the toggle (or `enabled:false` in `managed.json`): the
  service goes back to easytier-go with the local TOML.

Verified on the F50 (2026-10-21): after enabling with machine id `f50`, the
process was `easytier-official/easytier-core -w udp://easytier.wx2020.cn:22020/wx2020
--machine-id f50`, and its log showed
`Web client started successfully` and `Successfully connected to ... udp://easytier.wx2020.cn:22020`.
The machine must be registered in the console before the console pushes a
network config; until then the node has no overlay peers.

Peer table in managed mode: the official `easytier-cli -o json peer` returns an
**array** with `cidr` / `lat_ms` / `cost` (`p2p`, `relay(2)`, `Local`), while
the Go CLI returns `{"peers":[{id,hostname,ipv4,latency_ms,next_hop,cost}]}`.
The CGI normalises both shapes; before that the LuCI table was empty because
`status.peers.peers` was undefined. The normaliser uses only jq builtins (the
F50's jq is built without Oniguruma, so `sub()`/`match()` are unavailable).

## Notes / limitations

- The F50 uses plain-file deployment because it has no opkg. The `.ipk` is
  for standard OpenWrt; the plain tarball is the supported path here.
- The Go core needs root (`/dev/net/tun` + interface/route setup). procd runs
  it as root.
- The dashboard uses `easytier-cli -o json peer|route`; the Go management
  `peer`/`route` endpoints were extended in this task to expose OSPF
  hostname/IP/version/next-hop/cost.
- Ping RTT is 50–900 ms depending on the 5G link; loss was 0% in the final
  test. The earlier 100% loss was caused by (a) sing-box table 2022 capturing
  the overlay and (b) the Go TUN runner stopping on a send error; both are
  fixed.
- `logs` uses `logread` (procd stdout/stderr). No separate log file is
  configured.

Evidence files: `.tmp/f50/before.txt`, `.tmp/f50/final.txt`.
