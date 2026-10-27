# EasyTier Go Rewrite Software Engineering Design

## 1. Objective

Replace the Rust EasyTier 2.6.4 implementation with a production-quality Go implementation while preserving externally observable behavior. The implementation must be protocol-compatible with Rust 2.6.4 during migration and must retain the shipped products, integrations, and supported target platforms recorded in `GO_REWRITE_TODOLIST.md`.

This is a clean-room behavioral reimplementation. Rust source is used as a compatibility specification and test oracle. The Go code must not depend on a Rust core at runtime.

## 2. Non-negotiable contracts

1. Preserve binaries `easytier-core` and `easytier-cli` and their command-line/configuration contracts.
2. Preserve TOML configuration field names, defaults, absent-versus-empty behavior, environment expansion, and persistence restrictions.
3. Preserve peer-visible wire formats, protobuf field numbers and method ordering, management RPC transport, and web-control transport.
4. Preserve security behavior: network identity, credentials, X25519 keys, Noise handshakes, encrypted-session replay protection, ACL enforcement, and RPC source whitelist.
5. Preserve operational behavior: TUN lifecycle, routes, DNS, services, installers, package names, drivers, FFI/JNI ownership, and mobile TUN FD handling.
6. Do not claim a protocol, target, or feature complete until bidirectional Go/Rust 2.6.4 tests pass.

## 3. Architecture

### 3.1 Module layout

The Go workspace will use independently testable modules:

```text
go.work
cmd/easytier-core/          daemon binary
cmd/easytier-cli/           management CLI
internal/config/            TOML, CLI, environment, validation
internal/proto/             generated protobuf bindings and descriptor metadata
internal/transport/         TCP, UDP, WS/WSS, WG, QUIC, fake-TCP, Unix
internal/peer/              packet codec, sessions, routing, relaying, credentials
internal/nat/               STUN, UPnP, NAT-PMP, hole punching
internal/overlay/           TUN, packet forwarding, proxies, ACL, DNS, portal
internal/rpc/               custom RPC framing, standalone API, services
internal/platform/          per-OS interface, route, DNS, service, driver adapters
internal/webclient/         config-server client and secure channel
web/                        Go web control-plane service
ffi/                        C ABI and headers
jni/                        JNI and Kotlin bindings
adapters/android/           VpnService integration
adapters/ohos/              N-API/HAR integration
contrib/uptime/             uptime service
testdata/compat/            versioned Rust 2.6.4 golden vectors
tests/interop/              Go/Rust bidirectional integration tests
```

Packages expose narrow interfaces. `internal/peer` never imports OS-specific code. Platform code receives packet I/O and desired network state through interfaces owned by `internal/overlay`.

### 3.2 Runtime composition

`easytier-core` performs the following sequence:

1. Parse CLI/environment/config sources and build validated immutable instance configurations.
2. Start an instance manager and standalone RPC portal.
3. For every instance, construct identity, transport listeners/connectors, peer manager, route engine, ACL, virtual NIC, gateways, DNS, VPN portal, metrics, and web client.
4. Run all components under a context-bound supervisor. A failed child returns a typed error and triggers deterministic shutdown/cleanup.
5. Apply dynamic configuration changes through transactional RPC operations: validate, construct replacement components, atomically publish state, then drain old components.

No component may start goroutines outside the owning context. Every socket, TUN FD, route, DNS resolver change, mapping lease, timer, and temporary file must have a close/rollback path.

### 3.3 Concurrency

Go contexts govern instance, peer, connection, and request lifetimes. Shared mutable state is partitioned by instance:

1. Immutable configuration snapshots are atomically published.
2. Peer state is guarded by fine-grained locks or a single owner event loop where ordering is protocol-significant.
3. Packet paths use bounded queues with explicit drop/backpressure counters.
4. RPC calls carry deadlines and cancellation.
5. The race detector is mandatory for unit and integration tests on supported host platforms.

## 4. Protocol design

### 4.1 Packet and stream framing

The base `PeerManagerHeader` is exactly 16 bytes, little endian:

```text
0..3   from_peer_id u32
4..7   to_peer_id u32
8      packet_type u8
9      flags u8
10     forward_counter u8
11     reserved u8
12..15 payload_length u32
```

TCP and Unix use `u32 little-endian frame_length` followed by the complete peer packet. Frame length includes the header. WebSocket messages are complete peer packets without the 4-byte stream length. UDP adds its 8-byte connection header before a peer packet. All bounds checks occur before allocation.

When `COMPRESSED` is set, the payload is `compressed_bytes || algorithm_u8`,
where `algorithm_u8=1` is zstd. The header length remains the original
uncompressed payload length. Compression is used only when the compressed bytes
plus the one-byte algorithm tail are smaller; decryption precedes decompression,
and decompression must reproduce the header length exactly.

The compatibility suite owns byte fixtures for every packet type, encrypted/compressed payload, malformed header, max-size boundary, and foreign-network nesting case.

### 4.2 Transport abstraction

```go
type Tunnel interface {
    Recv(context.Context) (Packet, error)
    Send(context.Context, Packet) error
    Close() error
    Endpoint() Endpoint
}
```

Supported tunnel URLs are `tcp`, `udp`, `wg`, `quic`, `ws`, `wss`, `faketcp`, `unix`, and `ring`. Connectors additionally support `http`, `https`, `txt`, and `srv`. URL parsing, default ports, listener shorthand expansion, and advertised addresses must match the reference.

QUIC is not considered complete until it interoperates with `quinn-plaintext`; ordinary TLS QUIC is not a substitute. Fake-TCP remains behind a platform capability interface because it requires privileged packet capture/injection.

### 4.3 Sessions and cryptography

Unsecured peers use the legacy protobuf handshake. Secure direct sessions use `Noise_XX_25519_ChaChaPoly_SHA256` and secure relay sessions use `Noise_IK_25519_ChaChaPoly_SHA256`, with the reference prologues, message protobufs, connection UUID checks, and network-secret proof.

Session traffic encryption has exact tail layout:

```text
ciphertext || tag[16] || nonce[12]
```

Nonce, traffic key derivation, direction selection, epoch rotation, replay window, previous-epoch lifetime, future-epoch bound, and consecutive-decryption failure handling are conformance-tested from Rust-generated vectors. The outer peer header has empty AEAD AAD, matching the reference.

Use maintained Go cryptographic libraries. Do not substitute an approximate Noise implementation or an incompatible KDF.

Current implementation status: the Go secure-session slice implements Noise XX, the reference prologue, peer packet types 13/14/15, Rust-compatible protobuf message codecs and fixture vectors, static-key pinning, network-secret proofs, root-key distribution, TCP/UDP Go-to-Go tests, sender-driven epoch advancement, and AES-128/AES-256/ChaCha20 selection. Real Rust 2.6.4 byte-for-byte secure-handshake interoperability remains a required NET-09 gate.

### 4.4 Routing and relay

The route engine maintains a distributed graph from peer routing messages, computes least-cost and latency-first routes, distributes proxy CIDRs/manual routes/exit nodes/features/credentials/foreign networks, and updates packet forwarding state atomically. Forwarding increments `forward_counter`; packets past reference limits are dropped and measured.

Relay policies are checked before any forward. Foreign-network envelopes are parsed with strict offset/length validation. Routing tests run Go-only and mixed Go/Rust topologies with fixed expected paths.

### 4.5 NAT traversal

NAT traversal is an isolated service with interfaces for STUN, port mapping, socket binding, direct-connection signaling, and hole-punch strategies. It supports IPv4/IPv6 STUN, cone and symmetric NAT cases, UDP/TCP punching, UPnP IGD, NAT-PMP, and mapping renewals.

Timing-sensitive tests run against controllable local NAT/router emulators. Tests must not depend solely on public-network behavior.

## 5. Overlay and policy design

### 5.1 Virtual NIC and routing

`overlay.NIC` owns packet ingress/egress and delegates TUN creation/configuration to `platform.NIC`. It supports supplied mobile TUN FDs, static addresses, DHCP selection, IPv6, MTU, route installation, no-TUN mode, and complete rollback. The core does not shell out directly except within a platform adapter with tested argument construction.

### 5.2 Gateways

Gateways include subnet proxying, CIDR remapping, exit-node/system forwarding, TCP/UDP/ICMP forwarding, SOCKS5, TCP/UDP port forwarding, protected-port whitelists, KCP proxy, QUIC proxy, and optional user-space TCP/IP stack. Packet parsing must be zero-copy where safe, but safety and bounded memory prevail over performance claims.

### 5.3 ACL

ACL processing is applied at inbound, outbound, and forwarded/subnet boundaries. Rules have stable ordering, protocol/CIDR/port/group matches, actions, token-bucket rate limits, state tracking, and metrics. A configuration update builds a new compiled policy then atomically replaces it; in-flight flow state remains safe.

### 5.4 Magic DNS and VPN portal

Magic DNS maintains distributed records through the internal RPC API, serves the configured overlay zone, forwards non-overlay queries upstream, and delegates resolver configuration to platform adapters. It must restore the host resolver on shutdown.

The VPN portal implements standards-compatible WireGuard client access while retaining EasyTier's deterministic key derivation and generated configuration format. It maps authenticated client traffic into overlay routing only after source-address validation.

## 6. Management and web APIs

### 6.1 Custom RPC

The standalone management port is not gRPC. It is the EasyTier custom RPC layer over TCP tunnel frames. Generated protobuf types are necessary but insufficient: the implementation must preserve `RpcDescriptor`, method indices, fragments, compression, error encoding, traces, response matching, timeout, and the UDP payload budget.

The RPC portal defaults to `127.0.0.1:15888` and restricts source CIDRs before request parsing. All RPC methods listed in `API-04` have a contract test generated from descriptors and examples.

### 6.2 CLI

The Go CLI talks only to the custom standalone API. It preserves table/JSON output and all current command families. With no instance selector, it discovers instances and fans out operations using the reference ordering and JSON wrapper behavior.

### 6.3 Web control plane

The web service is a separate product. It owns SQLite migrations, user/session/RBAC/auth flows, REST endpoints, config-server sessions, remote instance control, webhooks, and frontend asset hosting. The config-server transport supports TCP/UDP/WS plus the optional reference Noise upgrade. Persisted schema migrations are append-only and are tested against preexisting databases.

## 7. Platform adapters

The platform layer has no protocol authority. It receives declarative desired state and returns typed capabilities/errors.

| Platform | Required responsibilities |
| --- | --- |
| Linux | TUN, netlink routes/addresses, DNS/resolved integration, namespaces, systemd/OpenRC, bind-to-device |
| Windows | Wintun, WinDivert fake-TCP, routes, DNS, firewall, Windows service manager, driver packaging |
| macOS | TUN/network extension where applicable, routes, DNS resolver integration, launchd |
| FreeBSD | TUN, routes, resolver integration, rc.d |
| Android | supplied `VpnService` TUN FD, JNI, one-active-TUN policy, APK/Magisk lifecycle |
| OHOS | N-API bridge, config store, socket/TUN bridge, HAR packaging |

Each adapter has a dry-run planner used for unit tests and a privileged integration suite used on its native CI runner/device.

## 8. Test and quality strategy

### 8.1 Test layers

1. Unit tests: parsers, codecs, crypto, routes, ACL, config, and lifecycle state machines.
2. Golden vectors: Rust 2.6.4 packets, protobuf descriptors, config outputs, security handshakes, and deterministic keys.
3. Bidirectional interoperability: Go client to Rust server and Rust client to Go server.
4. Network namespaces/emulators: NAT, IPv4, IPv6, route, DNS, multi-hop, relay, loss, and failure recovery.
5. Native integration: real TUN, service, DNS, mobile, drivers, installers, and packages.
6. Security/performance: fuzzing, race detector, static analysis, dependency scanning, load, soak, failover, and leak tests.

### 8.2 Required interoperability matrix

Every release tests both directions (Go→Rust and Rust→Go) for TCP, UDP,
WS/WSS, WG, QUIC, fake-TCP where supported, secure/non-secure modes,
encryption algorithms, compression, direct peers, relays, foreign networks,
credentials, routing, subnet proxies, DNS, VPN portal, custom RPC, and web
control. A feature is absent from release notes if the matching matrix cell is
unavailable.

The executable matrix is defined in `docs/GO_REWRITE_TODOLIST.md` §7.4 and
executed by `.github/workflows/interop.yml`. The blocking release matrix
requires at minimum: `tcp/udp/ws/wss/unix` × (`legacy`, `Noise_XX`,
`Noise_XX` with pinned static) × (AES-128-GCM, AES-256-GCM, ChaCha20) ×
(`none`/`zstd`) for direct peers, 1-hop relay, and 3-node convergence; plus
mixed Go/Rust RPC (`API-04`) and config-server lifecycle (`WEB-01`). Cells for
WG, QUIC plaintext, and fake-TCP remain gated by `NET-06/07/08`.

Each cell starts an oracle node at `official-release`/`8428a89d` and a Go node
from `go/`, completes the handshake, exchanges `Ping`/`Data`/`RPC` payloads,
and captures packets on failure. The workflow aggregates results in a required
`interop-result` check; `VAL-02` may not be marked `complete` until the matrix
is green for 3 consecutive runs on `ubuntu-latest`.

### 8.2.1 Fixture corpus and oracle

The fixture corpus under `go/testdata/compat/` is the versioned oracle for
all golden-vector tests (§8.1.2). It is generated by the Rust 2.6.4 oracle
(`rust-toolchain 1.95`) and checked in CI by the `fixture-corpus` job in
`interop.yml`. Go packages `internal/protocol`, `internal/peer`,
`internal/rpc`, `internal/config`, and `internal/credential` assert
byte-for-byte equality against these vectors. Any change to the corpus
requires a migration record per §11.

### 8.3 Security requirements

1. No unbounded packet allocation, fragment accumulation, connection map, route map, or queue.
2. Secrets are redacted from logs, metrics, error strings, and UI responses.
3. RPC control access is deny-by-default outside the explicit whitelist.
4. All config mutation is authorized, validated, atomic, auditable, and rollback-safe.
5. Cryptographic behavior is vector-tested; custom crypto is prohibited.
6. Dependency updates receive automated vulnerability scanning and SBOM regeneration.

## 9. Delivery phases and gates

1. Foundation: FND-01 through FND-05. Gate: reproducible toolchain and Rust oracle fixtures.
2. Compatible node: CFG-01 through NET-11. Gate: Go/Rust direct TCP, UDP, WS, WG sessions, secure mode, and config parity.
3. Reachability: P2P-01 through P2P-07. Gate: mixed topologies, NAT traversal, routes, relays, and IPv6.
4. Usable overlay: GWY-01 through GWY-09. Gate: real application traffic through TUN, proxies, policies, DNS, and portal.
5. Operability: API-01 through WEB-04 and GUI-01 through GUI-02. Gate: Rust/Go management and existing frontends manage Go nodes.
6. Product parity: UPT-01, NTV-01 through NTV-07, REL-01. Gate: all published artifacts install and work on their target platforms.
7. Cutover: VAL-01 through VAL-05. Gate: independent release review and zero runtime dependency on Rust core.

No later phase substitutes for an incomplete earlier compatibility gate.

## 10. Known blocking risks

| Risk | Impact | Control |
| --- | --- | --- |
| Toolchain path differs from the usual distribution path | Automated environments may not expose Go on `PATH`. | Use `/usr/lib/go-1.24/bin/go` in the current environment and add a reproducible toolchain setup in FND-01. CI uses `actions/setup-go@v5` `1.24.0`. |
| Rust `DefaultHasher` is part of identity/key derivation | A naive Go hash breaks networks and portal keys. | Generate and lock Rust 2.6.4 test vectors before implementation. Vectors are now checked in under `go/testdata/compat/` via `interop.yml` `fixture-corpus`. |
| `quinn-plaintext` is not standard TLS QUIC | Stock Go QUIC does not interoperate. | Implement/carry a compatible transport and keep NET-07 blocked until proven. |
| Rust oracle requires `1.95` but images provide `1.85` | `FND-04` stays blocked and wire formats cannot be locked. | `interop.yml` installs `1.95` via `dtolnay/rust-toolchain@v1`; see `docs/GO_REWRITE_TODOLIST.md` §7.2. |
| Fake-TCP, Wintun, WinDivert, TUN, mobile, and OHOS are privilege/SDK-dependent | Host-only tests give false confidence. | Native CI/device matrix and adapter ownership. |
| Custom RPC method ordering is generated behavior | Stock gRPC is incompatible. | Compare descriptor sets and use generated method-index fixtures. |
| Existing config/web/FFI data must survive migration | Breaking change can strand deployed installations. | Versioned migration, fixtures, upgrade/rollback tests. |
| Scope is substantially larger than a single binary port | Partial implementation could be mislabeled complete. | Track every feature in the ToDo matrix and report only verified completion. |

## 11. Change control and clean-room policy

Any intentional behavior change requires a short design record containing the affected ToDo IDs, compatibility impact, migration procedure, security review, test updates, and release-note entry. The record must be approved before code merges. This rule prevents accidental divergence while the Rust implementation remains in production.

### 11.1 Clean-room compatibility policy (FND-03)

The Go rewrite is a **clean-room behavioral reimplementation** governed by `docs/CLEAN_ROOM.md`.

* **Oracle use:** Rust 2.6.4 (`official-release` / `8428a89d`) is the compatibility oracle. Go may observe Rust via running binaries, captured packets, TOML/RPC fixtures, and deterministic vectors under `go/testdata/compat/` (§8.2.1). Mechanical copy of Rust source text, comments, or non-trivial control flow into Go is prohibited; implementations must be written from the behavioral spec in §4 and the fixture corpus.
* **Protobuf:** `.proto` sources are interface specifications reused verbatim; Go regenerates bindings via `protoc 3.21.12`. Field numbers remain locked per `GO_REWRITE_TODOLIST.md` §7.3 and `TestDescriptorFieldNumbers`.
* **License/SPDX:** Primary license is `LGPL-3.0-only` (`LICENSE` and `LICENSES/LGPL-3.0-only.txt`). Every Go file carries `SPDX-FileCopyrightText: 2025 EasyTier Contributors` and `SPDX-License-Identifier: LGPL-3.0-only` (after any `//go:build` or `// Code generated` prefix). REUSE compliance is declared in `REUSE.toml`; `reuse lint` is expected to pass. Dependency licenses are tracked via `go.mod` and SBOM (see `docs/RELEASE.md`).
* **Contribution rule:** Go patches must reference ToDo ID(s), include unit + golden-vector tests, and pass `go vet` / `go test -race` / fixture-corpus diff. Reviews check for Rust text overlap and missing SPDX.

For the full policy, see `docs/CLEAN_ROOM.md`.

### 11.2 Release and supply-chain policy (FND-05)

Releases follow `docs/RELEASE.md`: semantic versioning tracks Rust `2.6.4` (e.g., `v2.6.4`, Go ldflags `-X main.version`), artifact naming is defined per target matrix (§5), builds are reproducible (`-trimpath`, `CGO_ENABLED=0`, `SOURCE_DATE_EPOCH`), and every artifact ships with a Syft-generated SBOM (`sbom.spdx.json`), `SHA256SUMS`, a cosign/GPG signature (`*.sig`/`*.pem`), and SLSA provenance. The workflow `.github/workflows/go-release.yml` implements this pipeline; see `docs/RELEASE.md` and `script/reproducible-build.sh`.

### 11.3 P3 transport completion records (NET-06, NET-08, VAL-02)

Records for the P3 (transport completion) work. All changes preserve the
wire formats and golden fixtures; each notes the deliberate behavioral
choice relative to the Rust oracle.

* **WG session timers (NET-06).** The Go `wg://` tunnel adds a per-session
  routine task mirroring the boringtun timers used by the oracle:
  REKEY_AFTER_TIME 120 s, REJECT_AFTER_TIME 180 s (keys refused on both the
  send and receive path), REKEY_TIMEOUT 5 s between handshake retries,
  REKEY_ATTEMPT_TIME 90 s after which the session is abandoned, and
  KEEPALIVE_TIMEOUT 10 s with a native keepalive body kind
  (`magic + kind=3`; sealed data always starts with AEAD type 4, so the
  kind space 1..3 is reserved). Handshakes are serialized per session so
  both sides adopt rotated keys in the same order. Compatibility impact:
  none on the wire; sessions now rekey instead of using static-key epochs
  indefinitely. Dial still returns before the handshake completes
  (documented in `wg_crypto.go`), unlike the oracle's blocking connect.
* **Bind-to-device opt-in (NET-08 adjacent).** The oracle resolves the
  bind device automatically (`BindDev::Auto`) whenever a listener binds a
  specific address; on Linux that requires CAP_NET_RAW (SO_BINDTODEVICE)
  and fails unprivileged listeners. The Go transport implements the same
  socket options (Linux SO_BINDTODEVICE, macOS IP_BOUND_IF/IPV6_BOUND_IF,
  Windows IP_UNICAST_IF/IPV6_UNICAST_IF) but keeps binding **opt-in** via
  `transport.BindDevice(...)` / the endpoint URL path (`wg://host:port/eth0`
  → device `eth0`, mirroring `TunnelUrl::bind_dev`). Default remains
  unbound so unprivileged operation keeps working. Migration: deployments
  needing interface pinning set the URL path device.
* **fake_tcp capture backends (NET-08).** Windows uses WinDivert 2.2 via
  runtime `WinDivert.dll` loading (SNIFF-mode reader + "false"-filter
  injection sender, as in `netfilter/windivert.rs`); the driver/DLL ships
  separately, and the TCP emulation fallback applies when it is absent.
  macOS uses `/dev/bpf*` in immediate mode (immediate/see-sent/HDRCMPLT/
  200 ms read timeout, Ethernet/Null/Loop/Raw datalinks). Packet selection
  uses the shared userspace filter (`faketcp_capture_filter.go`) instead
  of a kernel BPF program on macOS; the selected packet set is identical.
  Kernel filter compilation remains future work if capture CPU becomes a
  concern.
* **ring:// tunnel.** In-memory ring tunnel registered under the `ring://`
  scheme (`ListenRing`/`DialRing` plus `CreateRingTunnelPair`), mirroring
  `tunnel/ring.rs` semantics (two unidirectional bounded queues of 128,
  registry-driven connect). Test convenience; no wire impact.

### 11.4 P1 interop records (peer-center, QUIC)

* **peer-center wire format (PEER-01).** The Go peer-center RPC previously
  used JSON bodies over a `peer_center` service with zero-based method
  indexes. It now speaks the reference contract: service `PeerCenterRpc` in
  proto package `peer_rpc`, domain = network name, one-based method indexes
  (`ReportPeers` = 1, `GetGlobalPeerMap` = 2), and the reference protobuf
  messages (`ReportPeersRequest/Response`, `GetGlobalPeerMapRequest/Response`,
  `PeerInfoForGlobalMap`, `DirectConnectedPeerInfo`, `GlobalPeerMap`).
  The reference response carries no explicit no-update flag; the client
  treats a returned digest equal to its local digest as "no update". Digest
  values are implementation-internal (computed over the local map), so a
  cross-implementation client simply never short-circuits and always
  receives the map.
* **QUIC tunnel status (NET-07, updated 2026-10-20).** NET-07 is
  **in-progress**, not complete. The earlier descope record below is
  superseded: a pure-Go `quicwire` engine now implements the
  `quinn-plaintext 0.3.0` wire contract (RFC 9000 varints, Initial/Handshake
  and 1-RTT headers, SeaHash-64 checksum, TransportParameters TLV, Stream 0
  framing), and `quic://` is re-enabled on
  `DialPacketChannel`/`ListenPacketChannel`.
  Current evidence (interop run 35833639716): all `quic/*/rust_to_go` and
  relay cells are green; the four `quic/{legacy,noise_xx}/go_to_rust`
  direct/compressed cells fail because the Go client does not complete the
  handshake and `QUICSession.Receive` blocks in
  `quicwire.recvStreamBuffer.Read` without honoring its context, so the test
  times out. The receive path is being made context-aware and the Go client
  handshake is being aligned before those cells are moved back into the
  blocking matrix. The gateway-side QUIC **proxy** (`gateway/quic.go`) is
  unaffected.
* **Superseded descope record (2026-09).** The Go `quic://` tunnel was
  previously a Go-only test double (UDP SYN/SACK framing mimicking
  quinn-plaintext frames) and could not interoperate with the reference. It
  was removed from the public transport surface and the scheme rejected with
  `ErrQuicTunnelDisabled`. This record is kept for history only; it no longer
  describes the code.

### 11.5 Live interop fixes (2026-10-20, 100.64.0.2)

A live run against the official 2.6.4 node (`10.64.0.1/24`, Rust
`2.6.4-8428a89d`) and a temporary Rust oracle exposed four runtime-only gaps
that the Go-Go/interop fixtures did not cover. All fixes preserve the wire
contract; the Rust node accepts and displays the Go peers after them.

* **Random per-start peer ID (CFG-04 alignment).** The CLI passed the literal
  peer ID `2` to `cfg.LegacyIdentity`, so every Go node collided. The
  reference draws `rand::random::<u32>()` at each start
  (`easytier/src/peers/peer_manager.rs`). `newConfiguredCoreNode` now uses
  `randomPeerID()` (crypto/rand, zero remapped to 1). No wire change.
* **Management node ID.** `management.NodeInfo.ID` was the listener address;
  it now reports the local peer ID, matching the reference `node` row. The
  `node_id` metric label uses the same value.
* **CLI enables OSPF.** `NodeOptions.EnableOSPF` defaulted to false, so a CLI
  node established peer connections but exchanged no route information.
  `newConfiguredCoreNode` sets `EnableOSPF: true` and `OSPFDomain` to the
  network name. The core already implemented the flooder; only the CLI
  wiring was missing.
* **OSPF self-description fields.** `Advertisement` now carries `hostname`,
  `IPv4`, `IPv6`, `EasytierVersion` and `TCPNatType`, and
  `ospf_wire.go` maps them to/from the reference `RoutePeerInfo` fields
  (`hostname`, `ipv4_addr` + `network_length`, `ipv6_addr`,
  `easytier_version`, `tcp_nat_type`, plus
  `feature_flag.support_conn_list_sync`). Previously the Rust peer table
  showed the Go peer with an empty IPv4/hostname and `version unknown`; it now
  shows the Go overlay address, hostname, build version and live counters.
  The internal `Advertisement` encoding is not a wire contract; the
  `peer_rpc.RoutePeerInfo` protobuf field numbers are unchanged.

Evidence and command transcripts: `docs/INTEROP_LIVE_100.64.0.2.md`.

### 11.6 Linux TUN and overlay forwarding fixes (2026-10-20, F50)

The F50 deployment exposed that the daemon path still used the in-memory TUN
pair from `cmd/easytier-core`; `go/internal/platform/linux` already had a real
`/dev/net/tun` adapter. The following fixes are behavioral, not wire changes:

* **Real Linux TUN.** On `GOOS=linux`, `newConfiguredCoreNode` now creates a
  named TUN through `/dev/net/tun` (`IFF_TUN|IFF_NO_PI`), sets MTU/up, assigns
  the overlay address and adds the overlay network route. Non-Linux hosts keep
  the in-memory device for tests/desktop. The CLI no longer silently pretends
  a TUN exists.
* **Exact overlay-IP lookup.** `route.Flooder.PeerForIP` now matches the exact
  host address in `RoutePeerInfo.ipv4_addr` (for example `10.64.0.1`), not
  every address in the advertised `/24`. Matching the whole prefix made the
  local node answer for every peer in its subnet.
* **Next-hop forwarding from TUN.** `tunIngress` sets the destination peer ID
  and uses `PeerConnectionManager.SendPacket`, so multi-hop destinations go
  through the router's next hop. A send error is counted and dropped instead
  of terminating the TUN runner (which previously stopped all TUN reads after
  the first multi-hop failure). The fixed `TUNDestination` test path still
  uses a direct `Send`.
* **Management OSPF wiring.** `ServiceOptions.OSPFProvider` reads the flooder
  lazily (the CLI builds the management service before `serveManaged` has
  published `r.ospf`), and `PeerList` fills hostname/IP/version/next-hop/cost
  from the OSPF self-descriptions with a conn-info fallback. Stale LSAs from a
  restarted node (new random peer ID, same overlay IP) are de-duplicated,
  preferring the local entry.
* **Coexistence rule (LuCI packaging only).** The F50 init script adds
  `ip rule add to 10.64.0.0/24 lookup main priority 8990` so a pre-existing
  sing-box TUN (table 2022) does not capture the overlay, and removes it on
  stop. This is a deployment concern, not a core protocol change.

Live evidence: `docs/LUCI_EASYTIER_F50.md` and
`docs/INTEROP_LIVE_100.64.0.2.md`.

### 11.7 Web-console client protocol (2026-10-21)

- New package `go/internal/webconsole` speaks the config-server protocol the
  hosted console (easytier.wx2020.cn:22020) uses. It deliberately does **not**
  reuse the earlier `internal/webclient` framing (a JSON-ish registration
  message envelope invented for the Go vertical slice); the console speaks the
  common RPC layer over a tunnel.
- Reuse instead of a new RPC stack: `rpc.PeerRpcManager` already implements the
  RpcPacket framing, transaction table, request/response envelopes and
  fragmentation. `webconsole.Session` supplies a `rpc.RpcTransport` bound to a
  `transport.PacketChannel` and a read loop that feeds `HandlePacket`. Peer IDs
  are 1/1 and the RPC domain is empty, matching the reference
  `scoped_client(1, 1, "")` and `registry().register(..., "")`.
- Divergence: `rpc.PeerRpcManager.Register` now accepts an empty domain. The
  console registry keys services by `(domain="", service_name, proto_name)`, so
  rejecting an empty domain made the console services unregisterable. No
  existing caller changes behaviour (all pass a network name).
- Service names come from the proto service identifiers, which the reference
  generator emits unchanged (`proto_name == service name` for these types):
  `WebServerService` (methods 0 Heartbeat, 1 GetFeature), `WebClientService`
  (8 methods, declaration order), `ConfigRpc` (0 PatchConfig, 1 GetConfig).
- Noise upgrade reuses `webclient.UpgradeClientChannel` (magic
  `ET_WEB_NOISE_V1:`, prologue `easytier-webclient-noise-v1`,
  `Noise_NN_25519_ChaChaPoly_SHA256`), which the earlier work already pinned
  against the reference.
- `NetworkConfig` -> `config.Config` mapping follows the reference
  `gen_config()` semantics: instance id, hostname, dhcp, credential-mode
  identity, IPv4 prefix, networking method (unset keeps the reference default
  PublicServer and therefore requires `public_server_url`), listeners, proxy
  networks, port forwards, VPN portal, manual routes, exit nodes, socks5,
  mapped listeners, credential file, secure mode, and the flags block including
  the 26 advanced switches. `ValidateConfig` renders TOML through
  `config.Config.Marshal` rather than `Dump`: `Dump` routes the flags through a
  JSON map, which renames TOML keys to Go identifiers and cannot represent the
  `u64::MAX` "unlimited" sentinel.
- **Method indices are 1-based.** The reference generator emits
  `MethodDescriptor::X = declaration_index + 1` (0 is the "unknown" value), so
  `WebServerService.Heartbeat = 1`, `GetFeature = 2`, `WebClientService`
  methods are 1..8 and `ConfigRpc` 1..2. This was confirmed both in
  `easytier-rpc-build/src/lib.rs` and on the wire: the reference client calls
  method 2 for GetFeature and method 1 for Heartbeat. A 0-based table makes
  every call a silent "no such method" and the console retries forever.
- **Machine identity.** `--machine-id` accepts a UUID or hashes an arbitrary
  string into one. The hosted console stores the UUID the reference client
  derived, so a Go node must send that same value; capture it with the probe
  test below instead of re-deriving the reference's SipHash-1-3 derivation.
  `TestCaptureRealClientHeartbeat` (skipped unless `ET_CONSOLE_PROBE_ADDR` is
  set) listens with our own console implementation and prints the machine ID,
  hostname, version and token the client reports. Running the reference 2.6.4
  binary against it also proves tunnel/RPC interop in the other direction.
- **Noise data framing (fixed 2026-10-21).** The reference secure filter
  encrypts the *whole inner packet* — its 16-byte peer-manager header included —
  and sends it under a fresh `(from=0, to=0, PacketType=Data)` header with the
  encrypted flag set. `internal/webclient` used to encrypt only the payload and
  keep the original header, so the reference console decrypted a bare RpcPacket
  and silently dropped it: the handshake succeeded and every later RPC timed
  out. Both directions now wrap/unwrap the inner packet; `secureChannel` also
  re-parses it on receive.
- **Live console (2026-10-21).** Against `udp://easytier.wx2020.cn:22020/wx2020`
  the Go client works from the office network including the Noise upgrade
  (`GetFeature.support_encryption = true`, handshake completes, secure
  heartbeats answered). From the F50 the same client completes the Noise
  handshake but the console never answers the encrypted heartbeats, so the F50
  runs the plaintext tunnel (`ET_WEB_NO_NOISE=1`); plaintext heartbeats are
  answered there and the console pushed the `wx2020` config, creating
  `easytier0` with `10.64.0.50/24` and a listener on tcp/11010.
  Over IPv6 IPv4-literal UDL is degraded: the plaintext IPv4 path from the F50
  answered only sporadically, so the deployed unit points at the console's IPv6
  address. With that, the console polls `ListNetworkInstanceMeta` on the Go
  client and pushed the config; ICMP to `10.64.0.1` measured ~60ms and to
  `10.64.0.2` ~74ms, i.e. real mesh round trips. Peer coverage is still partial
  (some peers answer, others do not) and the peer table is only visible through
  the daemon's 30s diagnostic line, so "8 peers" is not established yet.
- **Remote proxy routes (2026-10-21).** The Go daemon did not install kernel
  routes for proxy networks advertised by remote peers, so switching a node to
  the Go core silently removed reachability to peer subnets (the reference
  installs one route per learned proxy CIDR). `core.ProxyRouteManager` now
  diffs the desired CIDR set (union of OSPF advertisements, excluding the local
  peer) against what it installed, executes `platform.PlanRoutes` /
  `CleanupRoutes` commands, keeps bookkeeping across failures (a failed add is
  retried on the next sync), and clears everything when the instance closes.
  The instance polls the OSPF table every 10s and logs installs/withdrawals.
- **Route cost unit and the direct data path (2026-10-21, open).** The peer
  table shows a "next hop" and a "cost" taken from the OSPF route table, and
  the dashboard renders DIRECT when the next hop is the peer itself. The
  reference numbers a route's cost in **hops** (its route cost calculator
  returns 1 for a connected pair) and reports the latency in a separate
  `path_latency` field. This Go core advertised its own direct links with the
  **smoothed latency in milliseconds**, so a direct link priced at 194 ms
  looked more expensive than a two-hop relay path priced 1 + 1, and the router
  kept sending traffic through the relay while the dashboard dutifully
  reported "next hop qcloud-sh" for peers the node was directly connected to.
  Switching the advertisement to the hop cost makes the table correct (next
  hop = the peer, cost 1) **but is not safe yet**: with hop costs the route
  table prefers the direct session, and the direct session currently carries
  control traffic only - the peer's latency probes answer while TUN payloads
  to that peer never arrive - so traffic to the directly connected peers would
  be dropped instead of relayed. The advertisement therefore keeps the latency
  price until the direct data path is fixed; the switch is a one-line change
  in `nodeRuntime.directLinkCosts`.
- **Peer-to-peer direct connections (2026-10-21, three-part fix).** The Go
  node kept a single direct peer (the configured public server) and relayed
  everything else, because every NAT-traversal RPC to a reference peer failed.
  Three independent mismatches had to be corrected at once:
  1. **Method indices**: the reference generator numbers methods from one
     (`index = position + 1`); `DirectConnectorRpc` (GetIpList=1,
     SendUdpHolePunchPacket=2), `UdpHolePunchRpc` (1..5) and
     `TcpHolePunchRpc` (ExchangeMappedAddr=1) were 0-based here.
  2. **Descriptor proto name**: the reference registry keys services by
     (domain, service name, proto name) and the proto name equals the service
     name for the peer_rpc family; the client used the placeholder
     `"EasyTier"`. `rpc.PeerRpcManager.CallService` now sends the real name.
  3. **Body encoding**: the reference peer_rpc services exchange **protobuf**
     bodies (the generated `call`, not the `json_call_method` variant); the Go
     client and server used protojson. After the switch the reference peer
     answers instead of returning `prost_decode_error`.
  Symptom ladder that identified them: no outbound dials at all (RPC failed
  before dialing) -> `prost_decode_error:{}` (service found, body encoding
  wrong) -> direct connections established.
  Result on the F50: **7 direct peers** (was 1), per-peer latencies visible in
  the dashboard, `ping 10.64.0.1` average RTT down from ~119ms to ~70ms and
  `10.64.0.9` became reachable (~200ms) where it previously timed out.
  Regression guards: `internal/directconn/wire_identity_test.go`,
  `internal/rpc/call_service_test.go`, `internal/punch/method_index_test.go`,
  `internal/tcphole/method_index_test.go`.
- **Console peer table rendering (2026-10-21, two follow-ups).** The console
  renders the machine's peer table from `CollectNetworkInfo`, and its
  Vue template dereferences `route.feature_flag.is_public_server` for every row
  with a non-zero cost. A missing `feature_flag` therefore throws in the
  browser and the whole table renders empty - the symptom was a blank peer
  table with a node count of zero. Every route now carries an empty
  `feature_flag`, which keeps the template's expression valid.
  The table also lists our own node, so the local advertisement is filtered
  out of the peer list.
- **Ping/pong matching (2026-10-21).** A ping may be answered by a node other
  than the peer that was pinged, and the reference echoes a ping without
  swapping the header, so the answer still carries the original addressee.
  Dispatching the pong by the sender's peer id therefore handed it to the
  wrong pinger, which showed up as a constant 50% loss and a wrong latency.
  The ping sequence numbers are now globally unique per node and a pong is
  routed to the pinger that is waiting for that sequence number.
- **Console peer table rendering (2026-10-21).** The hosted console renders
  the machine's peer table from `CollectNetworkInfo`. Reporting only peer IDs
  left every column empty and the latency column as NaN. The response now
  carries the same structures the reference fills: `my_node_info` (virtual
  IPv4, hostname, version, peer id, listeners), `routes` (peer id, IPv4
  address, next hop, cost, path latency, hostname, version, proxy CIDRs),
  `peers` with one `PeerConnInfo` per peer (connection id, tunnel type p2p or
  relay, statistics, loss rate, network name) and the `peer_route_pairs` that
  join them. Per-connection byte and packet counters were added to
  `PeerSession` so the console's upload/download columns are real numbers
  instead of zeroes.
- **Peer latency semantics (2026-10-21).** Three reference behaviours were
  missing and made the reported peer latency disagree with a fresh ping:
  1. **Control packets are never encrypted** on a secured peer session. The
     reference skips Ping/Pong in `should_skip_encrypt` on the send side and
     does not decrypt them on the receive side. This core encrypted them, so a
     reference peer dropped our pings: the pinger hit five consecutive
     losses, stopped, and the peer table kept a frozen number.
  2. **Five consecutive ping losses disconnect the peer** (the reference
     comment says "disconnect the connection if lost 5 pingpong
     consecutively"). We only stopped the pinger and kept the dead session,
     so the window never refreshed. `PeerConnectionManager.ClosePeer` now drops
     the session so the connector re-establishes it and the pinger restarts.
  3. **The reference pings once per second and averages the last 15 samples**
     (`WindowLatency::new(15)`). We averaged 100 samples and backed the ping
     rate off exponentially (up to 32x) when the link looked idle, so the
     number was up to a minute old. The backoff is gone and the latency
     window is 15 samples.
  The reported number is also *whose* round trip it is: a ping addressed to a
  peer can be answered by the node that relays it, so the reference reports the
  peer's own RTT only for directly connected peers and the path latency for
  relayed ones. The console status file now follows that rule
  (`pathLatencyMS`).
- **Race gate on a 386 host.** The installed Go is windows/386, so
  `go test -race` cannot run natively. Building the race binaries for
  windows/amd64 with the local mingw C toolchain works and the binaries execute
  on this x64 machine:
  `CGO_ENABLED=1 GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go test -race ./...`.
  The run found one real race, in a test helper reading a counter without its
  mutex; the counters now go through locked accessors.
- Verification at freeze: `go build ./...`, `go vet` on the touched packages,
  and `go test ./internal/webconsole ./internal/rpc` pass, including an
  in-process mock console that exercises registration -> GetFeature ->
  Heartbeat -> Run -> List/GetConfig/Patch/Collect/Meta/Retain/Delete.
- Not verified at freeze: the daemon `-w` path still instantiates the old
  `internal/webclient` client, so `easytier-core -w` does not yet host these
  services; the F50 has not been switched off the reference core. No live
  console evidence exists yet.

### 11.8 RPC response fragmentation (2026-10-27)

- **Symptom (live F50, console at easytier.wx2020.cn:22020):** the console
  listed the machine but every machine-detail fetch died. Daemon log:
  `webconsole session ended: handle webconsole rpc packet: UDP peer packet
  exceeds EasyTier limit: 2756` followed by `reconnecting in 30s`. The
  console saw method=8 (ListNetworkInstanceMeta, 26-byte answer) succeed and
  method=4 (CollectNetworkInfo, ~2.7 KB with 8-9 peers) kill the tunnel —
  so the machine page showed no established nodes.
- **Root cause:** `rpc.PeerRpcManager.sendResponse` hardcoded
  `TotalPieces: 1` and sent one datagram regardless of size. Requests were
  fragmented by `sendFragmented` (1300 B/piece, matching the reference
  `RPC_PACKET_CONTENT_MTU`), but responses were not. The UDP transport
  rejects any peer packet over `UDPMaxPayloadSize` (2000 B including the
  16-byte peer-manager header), so large responses tore the session down.
- **Reference behaviour:** `build_rpc_packet` →
  `split_rpc_content_for_udp_budget` fragments requests **and** responses
  identically against the 1300 B UDP budget
  (`easytier/src/proto/rpc_impl/packet.rs`). The Go path now mirrors that:
  `sendResponse` marshals the `RpcResponse` envelope and hands it to
  `sendFragmented(..., isRequest=false)`. Single-piece responses keep the
  legacy wire shape (`total_pieces=1`, descriptor on the piece).
- **Tests:** `rpc/response_fragment_test.go` — a ~10 KB response must split
  into pieces that each fit the UDP budget, carry sequential
  `piece_idx`/`total_pieces`, drop the descriptor after the first piece,
  and reassemble byte-identically; a small response must stay one piece
  with its descriptor.
- **Live verification (F50, Go core `-w`):** after deploying the rebuilt
  binary, method=4 is polled every ~7 s by the console with
  `running=true peers=8 routes=8`, zero `exceeds`/`session ended` events;
  `ping 10.64.0.1` 3/3; the console's `easytier-cli peer` on the server
  shows `f50 10.64.0.50/24 p2p 55 ms 0.0%`. Previous binary preserved at
  `/root/backup/easytier-core.bak-20261027-pre-respfrag` on the F50.
