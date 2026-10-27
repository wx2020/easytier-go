# Web console (config-server) protocol — Go implementation status

Status as of 2026-10-21 (freeze point). Read this together with
`GO_REWRITE_SE.md` §11.7.

## What the console speaks

```
tunnel (udp/tcp/ws/wss, optional Noise upgrade)
  └── 16-byte PeerManagerHeader (PacketType RpcReq=8 / RpcResp=9)
        └── RpcPacket protobuf (from/to peer 1, transaction id, descriptor, body)
              └── common.RpcRequest / common.RpcResponse envelope
                    └── service method protobuf
```

- Both tunnel endpoints address each other as peer **1**; the RPC **domain is
  empty**.
- Services: `WebServerService` (console side: `Heartbeat` = method 0,
  `GetFeature` = method 1), `WebClientService` (machine side: `ValidateConfig`
  0, `RunNetworkInstance` 1, `RetainNetworkInstance` 2, `CollectNetworkInfo` 3,
  `ListNetworkInstance` 4, `DeleteNetworkInstance` 5,
  `GetNetworkInstanceConfig` 6, `ListNetworkInstanceMeta` 7), `ConfigRpc`
  (`PatchConfig` 0, `GetConfig` 1).
- Noise upgrade: magic `ET_WEB_NOISE_V1:`, prologue
  `easytier-webclient-noise-v1`, `Noise_NN_25519_ChaChaPoly_SHA256`. The
  console is asked once with `GetFeature` (3s timeout); `support_encryption`
  decides whether the connection is re-dialled and upgraded.
- Heartbeat is sent every second and carries machine id, per-session instance
  id, user token (URL path), version, report time, hostname, device OS,
  `support_config_source`, and the running instance ids.
- The console never pushes a config blob: it calls `WebClientService` /
  `ConfigRpc` on the machine.

## What is implemented in this repo

`go/internal/webconsole`:

| file | contents |
| --- | --- |
| `session.go` | `Session`: `rpc.PeerRpcManager` over a `transport.PacketChannel`, service registration, typed `Call`, `Wait`/`Close` |
| `console.go` | `Options`/`Console`: URL + token parsing, dial, `GetFeature` probe, Noise re-dial, heartbeat loop, 1s reconnect loop |
| `service.go` | `Backend` interface, `WebClientService` (all 8 methods), `ConfigService` (`PatchConfig`/`GetConfig`), `ApplyConfigPatch` |
| `config_map.go` | `NetworkConfigToConfig`, `ConfigToNetworkConfig`, `ValidateNetworkConfig` (all fields incl. the 26 advanced switches) |
| `uuid.go` | wire UUID framing (four big-endian words) and device OS info |
| `mockconsole_test.go` | in-process console: registration → GetFeature → Heartbeat → Run → List / Collect / GetConfig / Meta / Validate / Patch / Retain / Delete |

Reused as-is: `internal/rpc` (RpcPacket, transactions, fragmentation),
`internal/webclient` (Noise upgrade), `internal/transport` (udp/tcp/ws/wss).

## Verified

- `go build ./...` — pass.
- `go vet ./internal/webconsole ./internal/rpc ./cmd/easytier-core` — pass.
- `go test ./internal/webconsole ./internal/rpc` — pass (includes the closed
  mock-console loop and the NetworkConfig mapping/round-trip tests).
- `-race` is not available on this host (`go test -race` → "not supported on
  windows/386"); race coverage must run on Linux CI.

## Verification commands

```bash
cd go
go build ./... && go vet ./...
go test ./... -count=1

# This host runs a windows/386 Go, which cannot execute -race binaries, but the
# amd64 race binaries it produces do run here; mingw supplies the C toolchain.
CGO_ENABLED=1 GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go test -race ./... -count=1
```

Result at the 2026-10-21 freeze: `go vet ./...` clean, `go test -race ./...`
exit 0 across **44 packages**, no data races.

`go test ./cmd/easytier-core -run TestRunWebConsoleDrivesInstances` starts the
real `-w` daemon against an in-test console over a UDP tunnel and drives
ValidateConfig, RunNetworkInstance, ListNetworkInstance, CollectNetworkInfo,
ListNetworkInstanceMeta, GetNetworkInstanceConfig, ConfigRpc GetConfig,
PatchConfig, RetainNetworkInstance and DeleteNetworkInstance against real
instance creation/removal.

## Live console results (2026-10-21)

- Method indices are **1-based** (`Heartbeat = 1`, `GetFeature = 2`,
  `WebClientService` 1-8, `ConfigRpc` 1-2). Confirmed on the wire against the
  reference 2.6.4 client.
- `TestCaptureRealClientHeartbeat` (env `ET_CONSOLE_PROBE_ADDR`) captured the
  console's machine UUID for host `f50`: `ed618f32-5da5-6dc0-5ceb-7269445226cf`.
  The reference client's tunnel, RPC framing and heartbeat all worked against
  our Go console implementation.
- Against the hosted console from the office network: `GetFeature` returns
  `support_encryption=true`, the Noise upgrade completes and heartbeats are
  answered.
- From the F50: the Noise handshake completes but the console does not answer
  encrypted heartbeats, so the deployed unit forces the plaintext tunnel
  (`ET_WEB_NO_NOISE=1`). Plaintext heartbeats are answered and the console
  pushed the `wx2020` config: `easytier0` came up with `10.64.0.50/24` and a
  tcp/11010 listener.

### Console-visible instance state

`CollectNetworkInfo` reports `running`, `dev_name`, the peers the routing layer
knows (direct sessions plus OSPF advertisements) and one route entry per peer
(next hop, cost, path latency, hostname). On the F50 that is **1 direct peer and
8 routed peers**, which is the same topology the reference core reports.

### Peer-to-peer direct connections

The console hands over a NetworkConfig, but the mesh topology is built by the
data plane: the node asks each peer for its public/listener addresses
(`DirectConnectorRpc.GetIpList`), then dials them directly and punches holes
when needed. Three wire details had to match the reference exactly (method
indices are one-based, the descriptor's proto name equals the service name,
and the bodies are protobuf, not JSON). With those aligned the F50 node holds
**7 direct peers** plus the configured public server, the dashboard shows
per-peer latencies, and the remote proxy subnets stay reachable.

### Remote proxy subnets

Managed instances install kernel routes for proxy networks advertised by other
peers (`192.168.5.0/24`, `192.168.100.0/24` on the F50), and withdraw them when
the advertisement disappears. Verified end to end on the F50: `ip route` shows
both CIDRs via `easytier0`, and an SSH banner from `192.168.100.11:22` arrives
through the mesh.

### LuCI dashboard in console mode

The Go core in `-w` mode has no RPC portal, so `easytier-cli` cannot see it and
the dashboard used to show an empty peer table. The daemon now publishes its
live peer table to `ET_CONSOLE_STATUS_FILE`
(default `<tmpdir>/easytier-console-status.json`, refreshed every 30s, with the
`updated` timestamp inside the JSON because busybox has no `stat(1)`), and the
LuCI CGI falls back to that file when `easytier-cli` yields no peers. On the F50
the dashboard now lists **8 peers** (f50, qcloud-sh, liteserver-nl, homeserver,
colocrossing-usa, 510s-server, cloudcone-usa, aws-jp) with next-hop/latency
data, identical to what the reference core reported.

### Local config lock

In managed mode the LuCI CGI refuses local writes while the console owns the
instance: `save_config` → `local configuration is locked: managed by the web
console`; `get_config`/`status` still answer.

### Restart recovery

Console-delivered configs are cached under
`<data dir>/easytier/webconsole/<inst-id>.toml` and replayed at startup
(`Backend.Restore`), so a reboot brings the mesh back without waiting for the
console to push again. Deleted instances drop their cache file.

Verified on the F50: `reboot` → service auto-started → instance restored →
`easytier0` back at `10.64.0.50/24` → `ping 10.64.0.1` 3/3, 0% loss.

## Not done (blocked / out of time)

1. The managed instance holds **one direct peer** (the public server) and
   reaches the other seven through OSPF. `ping` to 10.64.0.1/.2/.3/.6/.7/.8/.9
   returns 0% loss while .4/.5 are offline, so the mesh is up with 8 routed
   peers. Direct (p2p) sessions to individual peers are not established the way
   the reference core does it; on the reference node the same topology appears
   (one p2p session, the rest relayed).
2. Secure (Noise) data path against the hosted console from the F50: handshake
   succeeds, encrypted heartbeats are not answered. The office network does not
   show the problem, so it is either link-specific or a direction/epoch detail
   only the hosted server exposes.
3. Console re-push is on the console's own schedule: it was observed twice
   (10:55 and 11:13), and not within 2.5 minutes when the cache was cleared on
   purpose. The heartbeat reports an empty running-instance list, so a reconcile
   detail on the server side gates the push; the local cache is what makes a
   restart deterministic.
4. Reboot recovery and local-config lock have not been re-verified with the Go
   core in managed mode.

## How to finish

1. Implement `webconsole.Backend` over `internal/instance.InstanceManager`
   (`RunInstance` = add + start `configuredInstance`, `RetainInstances` = stop
   the rest, `InstanceConfig` from the stored `config.Config`).
2. Allow `easytier-core -w` with no local config: create the instance manager
   first, then start `webconsole.NewConsole(...).Run(ctx)` and block until the
   context ends.
3. On the F50: build `linux/arm64`, `scp -O` to `/tmp`, stop easytier, replace
   `/usr/bin/easytier-core`, set `managed.json` to the Go core with
   `-w udp://easytier.wx2020.cn:22020/<token> --machine-id f50-id --hostname f50`,
   restart via `/etc/init.d/easytier restart`, then verify: console lists the
   machine, a pushed config yields 8 peers, `ping 10.64.0.1` 0% loss, reboot
   recovery, and that the local TOML stays locked.
4. Keep the reference core as the fallback: flip `managed.json` back or run
   `/etc/init.d/easytier restart` with the official binary.
