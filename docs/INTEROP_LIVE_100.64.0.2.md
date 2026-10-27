# Live Interop — official EasyTier 2.6.4 on 100.64.0.2

Date: 2026-10-20 (UTC)
Go build: `v2.6.4-gointerop4` (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64`)
Rust oracle: `easytier-core 2.6.4-8428a89d` (`/root/software/easytier-linux-x86_64/`)

## Topology

The live node was **not restarted, stopped, or reconfigured**. A temporary
Rust 2.6.4 node (`rust-interop`, `10.64.0.251/24`) was started on the same
host with a separate listener and joined the network as an added peer. Two Go
nodes connected to that temporary oracle:

| Node | Role | Overlay IPv4 | Transport to oracle | Listeners |
| --- | --- | --- | --- | --- |
| `qcloud-sh` (PID 248211) | live official node | `10.64.0.1/24` | — | tcp/udp 11010, wg/ws 11011, wss 11012, RPC 15888 |
| `rust-interop` | temporary oracle | `10.64.0.251/24` | tcp to `127.0.0.1:11010` | tcp/udp `127.0.0.1:22010`, RPC 26888 |
| `go-tcp` | Go node | `10.64.0.250/24` | **TCP** to `127.0.0.1:22010` | tcp `0.0.0.0:21010`, RPC 25888 |
| `go-udp` | Go node | `10.64.0.249/24` | **UDP** to `127.0.0.1:22010` | udp `127.0.0.1:21020` + required tcp `127.0.0.1:21021`, RPC 25889 |

The Go nodes ran with `--no-tun` so no interface or route was added to the
live host. The temporary Rust node also ran with `--no-tun` and
`--bind-device false`.

## Before snapshot

```
pid=248211
STARTED Sat Jun 13 10:10:51 2026
/usr/local/bin/easytier-core -w udp://easytier.wx2020.cn:22020/wx2020
7 peers: 10.64.0.1 (Local), .2, .3, .6, .7, .8, .9
listeners: tcp/udp 11010, wg/ws 11011, wss 11012, RPC 15888
```

Full capture: `.tmp/live/out/before.txt`.

## During — Go TCP node

`easytier-cli -p 127.0.0.1:25888 -o json peer` on the Go node:

```json
{
  "peers": [
    {"id": 2791822000, "peer_count": 1}
  ]
}
```

Temporary Rust oracle peer table (after the Go node advertised its OSPF
self-description):

```text
| 10.64.0.251/24 | rust-interop | Local | -    | -    | -         | -         | -    | PortRestricted | 2.6.4-8428a89d     |
| 10.64.0.1/24   | qcloud-sh    | p2p   | 0.18 | 0.0% | 74.99 kB  | 113.53 kB | tcp  | PortRestricted | 2.6.4-8428a89d     |
| 10.64.0.250/24 | go-tcp       | p2p   | 0.18 | 0.0% | 18.32 kB  | 17.47 kB  | tcp  | PortRestricted | v2.6.4-gointerop4  |
```

Temporary Rust oracle route table:

```text
| 10.64.0.250/24 | go-tcp | | DIRECT | DIRECT | 0.192 | 1 | 500 | DIRECT | DIRECT | 1 | 500 | v2.6.4-gointerop4 |
```

Live node peer/route tables (it reaches the Go node through the temporary
oracle, hence `relay(2)` and the zero direct counters):

```text
| 10.64.0.250/24 | go-tcp | relay(2) | 2.00 | 0.0% | 0 B | 0 B | | PortRestricted | v2.6.4-gointerop4 |
| 10.64.0.250/24 | go-tcp | | 10.64.0.251/24 | rust-interop | 0.172 | 2 | 1000 | ... | v2.6.4-gointerop4 |
```

## During — Go UDP node

```text
| 10.64.0.249/24 | go-udp | p2p | 0.23 | 75.0% | 618 B | 7.36 kB | udp | PortRestricted | v2.6.4-gointerop4 |
| 10.64.0.250/24 | go-tcp | p2p | 0.20 | 0.0%  | 105.40 kB | 89.30 kB | tcp | PortRestricted | v2.6.4-gointerop4 |
```

The live node also listed `go-udp` and `go-tcp` in its route table with
`next_hop_ipv4 = 10.64.0.251/24` (`rust-interop`), confirming OSPF
convergence across the mixed mesh.

Full capture: `.tmp/live/out/during.txt`.
Oracle debug tail: `.tmp/live/out/rust-interop-tail.log`.

## Issues found and fixed

The first attempts exposed four real Go bugs that unit tests did not cover:

1. **Every Go node used peer ID 2.** `newConfiguredCoreNode` called
   `cfg.LegacyIdentity(2)`. The Rust reference draws a random `u32` at each
   start (`peer_manager.rs`: `let my_peer_id = rand::random()`). Fixed with
   `randomPeerID()` and a regression test.
2. **Management `node` reported the listener address as the node ID.**
   `NodeInfo.ID` was `node.Address().String()`. It now reports the local peer
   ID; `MetricLabels["node_id"]` uses the same value.
3. **The CLI never enabled OSPF.** `NodeOptions.EnableOSPF` defaulted to
   false, so the live/Go peers connected but no route information was
   exchanged. `newConfiguredCoreNode` now sets `EnableOSPF: true` and
   `OSPFDomain` to the network name.
4. **The Go OSPF LSA lacked the self-description fields.** The reference
   `RoutePeerInfo` carries `hostname`, `ipv4_addr`/`network_length`,
   `easytier_version`, `tcp_nat_type` and `feature_flag`; Go sent only origin,
   version, proxy CIDRs, NAT type and credentials. The Rust peer table
   therefore showed the Go peer with an empty IPv4/hostname and `version
   unknown`. `Advertisement` now carries these fields and
   `syncRequestFromAdvertisement` / `advertisementsFromSyncRequest` round-trip
   them. The Rust peer table now shows `10.64.0.250 go-tcp ... tcp ...
   v2.6.4-gointerop4` and traffic counters.

Tests added/updated:

- `go/cmd/easytier-core/main_test.go`: `TestRandomPeerIDIsNonZeroAndVaries`.
- `go/internal/route/ospf_wire_test.go`: round-trip now asserts hostname,
  IPv4, IPv6, build version and TCP NAT type.

Change record: `docs/GO_REWRITE_SE.md` §11.5.

## Limitations

- The Go CLI has no `ping` subcommand. With `--no-tun` the Go nodes cannot
  originate ICMP; data-plane evidence is the peer `rx`/`tx` counters above and
  the OSPF route entries. The ICMP test is performed from the F50 in
  `docs/LUCI_EASYTIER_F50.md` (Task 3).
- The UDP oracle cell showed 75% loss on the loopback/LOCAL path. The link
  stayed up and counters advanced, but this needs a separate look if UDP
  stability is a release criterion.
- `easytier-cli route` on the Go node returns
  `management operation is not supported by the configured runtime`; the Go
  management route endpoint is still a stub. Routing itself works (the Rust
  oracle's route table is the evidence).

## After cleanup

The temporary Go and Rust processes were terminated by exact PID, and
`/tmp/easytier-go-interop` was removed. No temporary listener remains.

```
pid=248211
STARTED Sat Jun 13 10:10:51 2026   (unchanged)
7 peers: 10.64.0.1 (Local), .2, .3, .6, .7, .8, .9   (== before)
listeners: tcp/udp 11010, wg/ws 11011, wss 11012, RPC 15888 (unchanged)
temporary ports 21010/21020/21021/22010/25888/25889/26888: none
```

Full capture: `.tmp/live/out/after.txt`.
