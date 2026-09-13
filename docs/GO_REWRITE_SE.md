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
* **QUIC tunnel descope (NET-07).** The Go `quic://` tunnel transport is a
  Go-only test double (UDP SYN/SACK framing mimicking quinn-plaintext
  frames) and cannot interoperate with the reference, which requires a
  patched plaintext quinn stack that no maintained Go QUIC library provides.
  Decision: the `quic://` scheme is **removed from the Go public transport
  surface** (`DialPacketChannel`/`ListenPacketChannel` reject it with
  `ErrQuicTunnelDisabled`); config vocabulary (`ProtocolQUIC`, port offsets,
  `--quic-listen-port`) remains accepted for compatibility but the tunnel
  cannot be established. The gateway-side QUIC **proxy** (`gateway/quic.go`,
  lossy-network proxy) is unaffected. Go-only transport exercises remain in
  the interop tests with explicit descope labeling. Restoring QUIC requires
  a real QUIC implementation interoperating with quinn-plaintext, tracked
  in `REWRITE_PROGRESS_TODO.md` P1.
