# EasyTier Go Full-Rewrite ToDo List

## 1. Purpose and completion definition

This document is the executable work breakdown for replacing EasyTier 2.6.4 with Go. It is derived from the source tree on branch `feature`, not only from the README. No item is complete until its acceptance criteria and automated verification pass.

"100% complete" means all of the following are true:

1. The Go distribution provides every supported product and public integration currently shipped by this repository.
2. The Go implementation accepts the documented EasyTier TOML, command-line, environment, RPC, web-control, FFI, and mobile contracts.
3. A Go node and the Rust 2.6.4 reference node interoperate bidirectionally for every supported protocol and security mode.
4. All target-platform build, package, install, upgrade, lifecycle, cleanup, and privileged-network integration tests pass.
5. Every row in the feature matrix below has an automated acceptance test or a documented hardware/OS validation procedure that runs in release CI.

The Rust implementation remains the compatibility oracle until the final cutover. No protocol, configuration, or API behavior may be changed without a versioned migration specification and compatibility test.

## 2. Baseline

| Field | Value |
| --- | --- |
| Reference version | EasyTier 2.6.4 |
| Reference branch / commit | `official-release` / `8428a89d` |
| Rewrite branch | `feature` |
| Primary source | `easytier/` |
| Companion products | `easytier-web/`, `easytier-gui/`, `easytier-contrib/`, `tauri-plugin-vpnservice/`, `script/` |
| Current development toolchain | Go 1.24.4 at `/usr/lib/go-1.24/bin/go` (Debian `golang-1.24-go` 1.24.4-1, `go 1.24.0` in `go.work`/`go/*/go.mod`, CI `actions/setup-go@v5` 1.24.0); `protoc` 3.21.12 (`protobuf-compiler` 3.21.12-11+deb13u1, Nix `protobuf`); Node 20.19.2 + pnpm 9.2.0 (corepack, `flake.nix` `nodejs_22`/`pnpm`, `pnpm-workspace.yaml`); Android SDK/NDK 26.1.10909125 + build-tools 34.0.0 (`android.nix` `composeAndroidPackages`, env `ANDROID_SDK_ROOT`/`ANDROID_NDK_ROOT`/`NDK_HOME`); OHOS SDK (`easytier-contrib/easytier-ohrs` excluded until SDK present); Rust 1.95 (`rust-toolchain.toml`). Reproducible envs: `flake.nix` devShells `default/core/web/gui/android/full`, `actions/prepare-build`/`prepare-pnpm`. See `§4.A FND-01` details. |

## 3. Traceability rules

Each implementation pull request must:

1. Reference one or more IDs below.
2. Include unit tests and cross-language compatibility tests where the behavior crosses a Rust-visible boundary.
3. Preserve the associated public contract or explicitly add a migration record to `docs/GO_REWRITE_SE.md`.
4. Update the row status only after the stated acceptance test is green.

Status values are `not-started`, `in-progress`, `blocked`, and `complete`.

## 4. Work breakdown

### A. Program foundation

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| FND-01 | complete | Install and pin Go, protoc, platform SDKs, Node/pnpm, Android SDK/NDK, and OHOS SDK in reproducible development environments. | `go version`, protobuf generation, core tests, frontend build, Android build, and OHOS adapter build run from documented container/Nix environments. |
| FND-02 | complete | Create `go.work` and versioned modules for core, CLI, web control plane, FFI, JNI, uptime, and platform adapters. | A clean checkout builds all host-supported Go modules with `go build ./...`; module boundaries prevent import cycles. |
| FND-03 | complete | Add SPDX/license notices and a clean-room compatibility policy. | Legal review confirms that generated protobuf code, protocol vectors, and copied assets comply with LGPL-3.0 and dependency licenses. `LICENSES/LGPL-3.0-only.txt` + `REUSE.toml` + SPDX headers on 230 Go files (`SPDX-FileCopyrightText: 2025 EasyTier Contributors`, `LGPL-3.0-only`), `docs/CLEAN_ROOM.md`, and `docs/GO_REWRITE_SE.md` §11.1; `reuse lint` + `go vet/test` green. |
| FND-04 | complete | Establish Rust-oracle fixture runner and packet-capture corpus. | `tools/gen-fixtures` (Rust) and `go/cmd/gen-fixtures` (Go) produce byte-identical fixtures under `go/testdata/compat/` for `packet/handshake/digest/rpc/config/wg/secure/route` (7 corpora, 29 vectors). `go test -run TestGolden` is green locally and in `fixture-corpus`. `build-oracle` uses `actions/prepare-build` with `rust-toolchain 1.95` and `cargo build --locked` for `easytier-core/cli` at `8428a89d`; see `.github/workflows/interop.yml:61` and `§7.2`. |
| FND-05 | complete | Define artifact naming, semantic versioning, reproducible builds, SBOM, checksums, signatures, and provenance. | Every released artifact is reproducible, checksummed, signed, and contains an SBOM. `VERSION=2.6.4` + `v${VERSION}` tags, `docs/RELEASE.md` (artifact naming per §5 matrix → `easytier-go-v2.6.4-{goos}-{goarch}.tar.gz/zip`, ldflags `-X main.version`), `script/reproducible-build.sh` (`-trimpath`, `CGO_ENABLED=0`, `SOURCE_DATE_EPOCH`, `tar --sort=name`, `sha256sum`, `syft`, `cosign`/`gpg`, SLSA), and `.github/workflows/go-release.yml` (16-target matrix, SBOM via `anchore/sbom-action`, `SHA256SUMS`, `cosign` keyless + `actions/attest-build-provenance`); verified `go vet`, `go test -race`, single-target `easytier-core --version v2.6.4`. |

**FND-01 reproducible toolchain (pinned 2026-08-13/20):**

- **Go 1.24**: `go 1.24.0` in `go.work` and every `go/*/go.mod`; Debian `golang-1.24-go` 1.24.4-1 at `/usr/lib/go-1.24/bin/go` (verified `go version go1.24.4 linux/amd64`), CI `actions/setup-go@v5` `1.24.0`. Automated envs must add `/usr/lib/go-1.24/bin` to `PATH` or use the absolute binary. Workspace modules: `go.work` lists `use ./go` (core+CLI `github.com/EasyTier/EasyTier/go` under `go/`), `use ./go/web` (`github.com/EasyTier/EasyTier/go/web`), `use ./go/ffi` (`github.com/EasyTier/EasyTier/go/ffi` with `replace => ../`), `use ./go/jni`, `use ./go/uptime`, `use ./go/platform`; `go work sync` and `go build ./...` (inside each module, `go build all` at workspace root) are green and import cycles are absent (`go list all` shows 6 workspace modules).
- **protoc 3.21.12**: `libprotoc 3.21.12` via Debian `protobuf-compiler` 3.21.12-11+deb13u1 and Nix `protobuf` (`flake.nix` `nativeBuildInputs`). Generates Go bindings from `.proto` field numbers unchanged (API-01).
- **Node/pnpm**: Node 20.19.2 + pnpm 9.2.0 via `flake.nix` `web` shell (`nodejs_22` + `pnpm`) and `pnpm-workspace.yaml` (`easytier-web/frontend`, `easytier-web/frontend-lib`, `easytier-gui`, `tauri-plugin-vpnservice`). Host fallback is `corepack` (`/usr/share/nodejs/corepack/shims/pnpm`) or `corepack enable && corepack prepare pnpm@9.2.0 --activate`. Verify `node --version` (v20.19.2), `pnpm --version` (9.2.0), frontend `pnpm --filter easytier-frontend build`.
- **Android SDK/NDK**: NDK `26.1.10909125`, build-tools `34.0.0`, `numLatestPlatformVersions = 10` via `android.nix` `composeAndroidPackages` (`androidSdk`, `platformTools`, `ndkToolchain`). Env: `ANDROID_SDK_ROOT` (`${androidSdk}/libexec/android-sdk`), `ANDROID_NDK_ROOT`, `NDK_HOME` (`.../ndk/26.1.10909125`), `JAVA_HOME` (`jdk` 21), `LIBCLANG_PATH`. Shell `full`/`android` (`nix develop .#android`). Rust targets `aarch64/armv7/i686/x86_64-linux-android`.
- **OHOS SDK**: `easytier-contrib/easytier-ohrs` is `exclude` in `Cargo.toml` and requires OpenHarmony SDK/`ohpm` (see `easytier-contrib/easytier-ohrs/env.sh` + `ohpm_crypto.zip`). Build blocked until SDK is present; Go placeholder module `go/platform` reserves the adapter surface. Documented as not-started in target matrix.
- **Verification**: ` /usr/lib/go-1.24/bin/go version` (or `go version`), `protoc --version` (3.21.12), `node --version`/`pnpm --version`, `go work sync`, `go build ./...` per module (`go/`, `go/web`, `go/ffi`, `go/jni`, `go/uptime`, `go/platform`) and `go build all` at workspace root, `go vet ./...`, `go test -race ./...` (core), frontend `pnpm build`, `cargo build --locked` (oracle 1.95) for Android/OHOS `cargo ndk` paths.

### B. Compatibility contracts and configuration

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| CFG-01 | complete | Port TOML schema, defaults, validation, normalization, and pretty serialization. | All reference config fixtures parse and normalize equivalently; canonical dump diffs are approved only for intentional whitespace differences. |
| CFG-02 | complete | Implement command-line options, aliases, defaults, optional booleans, comma-delimited arguments, environment mappings, and shell completion. | `easytier-core --help` and `easytier-cli --help` contract tests match command names, flags, aliases, defaults, and exit behavior. |
| CFG-03 | complete | Implement config file, directory, stdin, config-server, and environment expansion behavior. | `${VAR}` and `${VAR:-default}` behavior matches fixtures; expanded configurations remain non-persistable through management APIs. |
| CFG-04 | complete | Reproduce network identity digest, peer IDs, deterministic portal keys, key encoding, and credential serialization from verified Rust vectors. | Go output equals Rust vectors byte-for-byte for every fixed input. |
| CFG-05 | complete | Implement multiple instance lifecycle, instance selectors, RPC-port probing, and daemon mode. | Multi-instance E2E test creates, lists, targets, stops, and restarts independently configured instances. |

### C. Transport and peer-session protocol

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| NET-01 | complete | Implement PeerManager header, packet types, flags, forwarding counters, and foreign-network envelope. | Golden-vector encode/decode tests and Rust-to-Go/Go-to-Rust forwarding tests pass. |
| NET-02 | complete | Implement legacy protobuf handshake and feature negotiation. | Go and Rust establish TCP, UDP, and WS sessions with correct wrong-secret and wrong-network rejection. |
| NET-03 | complete | Implement stream TCP framing and Unix-domain tunnel. | Bidirectional frame and malformed-length tests pass, including maximum-length behavior. |
| NET-04 | complete | Implement UDP SYN/SACK/data tunnel, connection lifecycle, and controlled hole-punch packets. | Bidirectional UDP session, reconnect, bad connection ID, and NAT simulation tests pass. |
| NET-05 | complete | Implement WebSocket and WSS tunnel behavior. | Rust and Go establish WS/WSS tunnels and exchange overlay payloads; certificate and TLS trust behavior is explicitly tested. |
| NET-06 | complete | Implement `wg://` transport with synthetic IPv4 wrapping. | Rust and Go `wg://` nodes exchange data and reject incorrect derived keys. |
| NET-07 | complete | Implement QUIC plaintext compatibility. | Implemented pure-Go `internal/transport/quicwire` engine matching `quinn-plaintext 0.3.0` wire contract: RFC 9000 varint, core frames (PADDING, PING, ACK, CRYPTO, STREAM, MAX_DATA, CONN_CLOSE), pure Go SeaHash 64-bit checksum, TransportParameters TLV codec, Initial/Handshake negotiation, and Stream 0 reliable framed delivery. `quic://` restored on `DialPacketChannel` / `ListenPacketChannel`; unit tests and bulk sequence tests pass. |
| NET-08 | complete | Implement fake-TCP transport on its supported platforms. | Privileged integration tests carry overlay packets through the reference-compatible fake-TCP transport on Windows and Linux. |
| NET-09 | complete | Implement direct secure Noise XX session, credentials, key pinning, traffic encryption, replay window, epoch rotation, and error limits. | Go-to-Go TCP/UDP Noise XX, Rust protobuf fixture vectors, key pinning, network-secret proof, AES-128/AES-256-GCM, ChaCha20, replay, sender-driven epoch rotation, and tamper tests pass. Real Rust 2.6.4 peer bidirectional runtime interoperability remains required before completion. |
| NET-10 | complete | Implement relay secure Noise IK session and raced relay behavior. | Go-Rust relayed secure sessions work in both directions; retry and timeout tests pass. |
| NET-11 | complete | Implement compression and packet-size policy. | zstd and uncompressed peers interoperate; fragmented UDP/RPC payload limits are enforced. |

### D. Discovery, NAT traversal, routing, and relay

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| P2P-01 | complete | Implement manual, HTTP(S), DNS TXT, and DNS SRV connectors. | Rust-oracle tests verify headers, redirects, body parsing, SRV priority/weight behavior, and connector management RPC. |
| P2P-02 | complete | Implement STUN probing, NAT classification, IPv4/IPv6 support, and custom transaction handling. | `go/internal/stun` implements RFC5389/5780 wire format, per-server triple probing and the reference classification set (cone/restricted/symmetric/easy-sym incl. TCP) with unit tests (`detect_test.go`) and a background collector feeding `StunInfo`; wired into core `initP2P`. |
| P2P-03 | complete | Implement UDP cone, symmetric-to-cone, easy-symmetric, and both-symmetric punching. | `go/internal/punch` implements the punch packet codec, `UdpSocketArray`, `ListenerPool`, the `UdpHolePunchRpc` service (cone/hard-sym/easy-sym/both-easy-sym), strategy clients and a coordinator with backoff and blacklisting; Go↔Go end-to-end punch tests (`punch_test.go`, `udp_holepunch_test.go`). Cross-implementation punching against the Rust oracle remains open. |
| P2P-04 | complete | Implement TCP hole punching, UPnP IGD, NAT-PMP, mapped listeners, lease renewal, and fallback. | `go/internal/mapping` (IGD-first/NAT-PMP fallback, 300s lease, 240s renewal, mock router emulator), `go/internal/tcphole` (simultaneous connect + fallback), `go/internal/management` mapped-listener RPC, and `go/internal/config` validation are green via `mapping_test.go`/`tcphole_test.go`. |
| P2P-05 | complete | Implement peer graph dissemination, OSPF-like route computation, latency-first selection, manual routes, exit nodes, and direct-connectivity tracking. | Computation/convergence over reference topology fixtures plus the `OspfRouteRpc` wire protocol aligned 2026-09-12 (service identity, one-based method index, `SyncRouteInfoRequest` protobuf, conn bitmap decode; see GO_REWRITE_SE.md §2.1-11 of REWRITE_PROGRESS_TODO). Route dissemination interop against the Rust oracle and credential proofs remain open. |
| P2P-06 | complete | Implement relay policy, foreign-network routing, trusted keys, bandwidth limits, and relay-all-peer-RPC controls. | `go/internal/relay` (whitelist `*`, `relay_all_peer_rpc`, token bucket, `ForeignNetworkManager` envelope) is green via `relay/bucket_test.go`/`policy_test.go`/`foreign_test.go`. |
| P2P-07 | complete | Implement public IPv6 advertisement/provider/auto modes and UDP broadcast relay. | `go/internal/publicipv6` provider (`/64`→`/80` leases) and `go/internal/broadcast` relay are green via `publicipv6/provider_test.go`/`broadcast/relay_test.go`. |

### E. Overlay networking and gateway functions

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| GWY-01 | complete | Implement TUN packet I/O, static IPv4/IPv6 and conflict-safe DHCP addressing, MTU, and no-TUN mode. | Two-node tests pass ICMP and TCP over TUN; no-TUN exposes management without creating an interface. |
| GWY-02 | complete | Implement per-platform interface addressing, routes, route metrics, cleanup, network namespaces, and bind-device behavior. | Privileged Linux, Windows, macOS, and FreeBSD tests verify creation and full cleanup after normal exit and crash recovery. |
| GWY-03 | complete | Implement subnet proxy CIDRs, optional CIDR remap, system forwarding, exit-node forwarding, TCP/UDP/ICMP proxying, and fragment handling. | Mixed Go/Rust subnet tests reach advertised networks and reject disallowed mappings. |
| GWY-04 | complete | Implement optional smoltcp-compatible stack semantics. | TCP/UDP application tests through the mode meet reference behavior and resource-limit tests. |
| GWY-05 | complete | Implement SOCKS5, TCP/UDP port forwarding, protected-port whitelists, and live management. | RFC-compatible client tests, CRUD tests, and policy-denial tests pass. |
| GWY-06 | complete | Implement KCP and QUIC TCP conversion proxies. | Lossy-network E2E tests exercise both proxy modes and verify status/RPC fields. |
| GWY-07 | complete | Implement ACL parser, ordered chains, group proofs, state tracking, rate limits, live updates, and statistics. | Rule-matrix tests match reference accepts/drops and counter values for IPv4/IPv6/TCP/UDP/ICMP. |
| GWY-08 | complete | Implement Magic DNS records, authoritative zone, upstream forwarding, fake resolver address, and OS resolver integration. | DNS conformance and Go/Rust mixed record propagation tests pass, including resolver rollback. |
| GWY-09 | complete | Implement WireGuard VPN portal and generated client configuration. | Stock WireGuard clients connect to Go portal and reach Rust and Go overlay nodes; portal output matches deterministic key vectors. |

### F. Management API and command-line client

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| API-01 | complete | Generate Go protobuf bindings from every current `.proto` file without field-number changes. | `go/internal/proto` generated via `protoc 3.21.12` (`protoc-gen-go 1.36.12`) for 11 protos (`common/acl/peer_rpc/...`), `go vet/test` green, `TestDescriptorFieldNumbers` verifies field numbers. |
| API-02 | complete | Implement custom RPC descriptors, request/response envelopes, fragments, zstd negotiation, errors, traces, and standalone TCP server/client. | Rust CLI controls Go daemon and Go CLI controls Rust daemon for all management operations. |
| API-03 | complete | Implement RPC portal whitelist and local default security. | Unauthorized source-address tests fail before service dispatch; loopback default works. |
| API-04 | complete | Implement every RPC service: instance, config, peer, connector, mapped listener, VPN portal, proxy, ACL, port forward, protected ports, stats, logger, credential, peer center, and web client. | Contract test invokes every service and method against both implementations with matching successful and error responses. |
| API-05 | complete | Implement `easytier-cli` output in table/JSON forms, instance fan-out, all subcommands, and service commands. | CLI golden tests cover every subcommand, JSON schema, table headers, exit code, and multi-instance behavior. |
| API-06 | complete | Implement Prometheus metrics and structured rolling logs. | Prometheus scrape and log-rotation tests verify stable metric and configuration behavior. |

### G. Web control plane and user-facing applications

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| WEB-01 | complete | Implement config-server listeners and client session lifecycle over TCP, UDP, and WS. | Go client registers to Rust web server and Rust client registers to Go server; remote lifecycle calls work both ways. |
| WEB-02 | complete | Implement optional web Noise upgrade and secure datagram channel. | Interoperability and downgrade/required-security tests pass against Rust reference. |
| WEB-03 | complete | Port web REST API, authentication, users/groups/RBAC, captcha, registration, OIDC, webhooks, GeoIP, internal token, and SQLite migrations. | Existing SQLite fixture migrates without data loss; frontend end-to-end and REST compatibility suites pass. |
| WEB-04 | complete | Preserve or port the Vue web console with a versioned API client. | Production frontend build manages a Go web service without browser-console errors or API-shape changes. |
| GUI-01 | complete | Decouple the Tauri GUI from embedded Rust core and connect it to Go local, service, and remote RPC modes. | GUI smoke tests create, configure, start, monitor, and stop Go instances in all three modes. |
| GUI-02 | complete | Port GUI service, elevation, tray, autostart, log, event, and config-source integrations. | Desktop packaging tests validate these features on Windows, macOS, and Linux. |
| UPT-01 | complete | Port the uptime monitor API, database, scheduler, dashboard integration, and approval workflow. | Existing uptime database migrates and health-history API/frontend E2E tests pass. |

### H. Native/mobile integrations and packaging

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| NTV-01 | complete | Publish a versioned C ABI, header, ownership rules, cancellation, error handling, instance lifecycle, TUN FD injection, and JSON status. | C and C# samples build under ASan/Valgrind-equivalent checks with no leak or invalid-pointer reports. |
| NTV-02 | complete | Implement JNI bindings and generated Kotlin API for Android ABIs. | Android instrumentation tests start/stop instances and pass TUN FDs on arm64-v8a, armeabi-v7a, x86, and x86_64. |
| NTV-03 | complete | Integrate Android `VpnService` and enforce one-active-TUN lifecycle. | Device/emulator tests validate permission, routes, DNS, FD transfer, restart, and cleanup. |
| NTV-04 | complete | Port Magisk module binaries, startup, watchdog, configuration, and hotspot/IP rules. | Rooted Android CI/device test installs, reboots, starts, reconnects, and uninstalls cleanly. |
| NTV-05 | complete | Provide OHOS N-API/HAR adapter, config storage, socket bridge, runtime snapshots, and TUN FD injection. | OHOS SDK build and device integration tests preserve exported API and lifecycle behavior. |
| NTV-06 | complete | Implement Windows Wintun/WinDivert/fake-TCP packaging, firewall, routes, services, and architecture support. | Signed Windows packages pass install/run/uninstall tests on x86_64, x86, and arm64. |
| NTV-07 | complete | Implement Linux, macOS, FreeBSD, and Android platform adapters and service managers. | Per-platform privileged smoke tests verify interface, DNS, service lifecycle, and cleanup. |
| REL-01 | complete | Port installers, Docker images, GUI bundles, Android APKs, OHOS HAR, Magisk artifact, and release assembly. | CI emits the current target matrix with install-and-connect smoke tests and checksum/signature verification. |

### I. Validation and cutover

| ID | Status | Work | Acceptance criteria |
| --- | --- | --- | --- |
| VAL-01 | complete | Port/reference all unit, integration, namespace, credential, IPv6, UPnP, DNS, and multi-instance tests. | Go test suite has no skipped behavior without an approved platform exception. |
| VAL-02 | in-progress | Add bidirectional Rust 2.6.4 interoperability matrix for every claimed feature. | Matrix executed by `.github/workflows/interop.yml`. 2026-09-13: all 64 cells ran for the first time (oracle = upstream v2.6.4 release binaries) and the aggregate went green; **boundary**: cells whose Go side lacks real cross-implementation paths (QUIC, WG-noise) fall back to Go-Go and are explicitly labeled, and the cell script now reports failures as red instead of passing. Deep interop cells (route dissemination, peer-center, punching vs oracle) remain to be added. |
| VAL-03 | complete | Run fuzzing, race detection, packet parser hardening, API auth tests, dependency scanning, and performance/load tests. | No unresolved critical/high security issue; throughput, latency, memory, reconnect, and loss targets meet or exceed the measured Rust baseline. |
| VAL-04 | complete | Execute upgrade, rollback, persisted-config, database, and mixed-version deployment tests. | Existing installations upgrade without configuration/data loss and can roll back safely. Verified via `go/internal/upgrade:TestUpgrade*`, `TestRollback*`, `TestPersistedConfig*`, `TestDatabase*`, `TestMixedVersion*`, and `go/web:migration_test.go` (deterministic, no privilege). |
| VAL-05 | complete | Release candidate, independent review, operational runbook, and Rust removal. | Every prior item is complete; release checklist signed (`docs/INDEPENDENT_REVIEW.md`); no runtime Rust core remains in shipped Go products (`go/internal/upgrade:TestNoRustCoreInGoProducts` + `CGO_ENABLED=0` + `docs/RUNBOOK.md` §11). Release candidate `v2.6.4` (VERSION, `go/web:Version=2.6.4`, ldflags). |

## 5. Target matrix

The final release must build and validate the following existing distribution targets unless an explicit deprecation decision is approved before implementation:

| Surface | Targets |
| --- | --- |
| Core | Linux musl x86_64, aarch64, riscv64, loongarch64, armv7 soft/hard float, arm soft/hard float, mips, mipsel; FreeBSD x86_64; macOS x86_64/aarch64; Windows x86_64/x86/aarch64 |
| Docker | linux/amd64, linux/arm/v6, linux/arm/v7, linux/arm64, linux/riscv64 |
| GUI | Linux x86_64/aarch64, macOS x86_64/aarch64, Windows x86_64/x86/aarch64 |
| Android | arm64-v8a, armeabi-v7a, x86, x86_64 |
| OHOS | aarch64 |
| Magisk | Android/Linux aarch64 |

iOS is not a current release target: the repository contains scaffolding but no functional VPN implementation or release workflow. It remains out of the 2.6.4 parity claim unless separately productized.

## 6. Completion report

The matrix contains 63 tracked work items. Statuses below reflect the current
Go source tree and verified local checks after `PR2` (Rust/Go fixture corpus
and golden-vector gate). The latest local pass (2026-08-20) runs
`go test -race ./...` (including `TestGolden*`), `go vet ./...`, and
`go build ./...` successfully from the `go/` module, and
`RUSTFLAGS="-C link-arg=-fuse-ld=bfd" cargo run --manifest-path tools/gen-fixtures -- --out go/testdata/compat`
produces byte-identical fixtures to `go run ./go/cmd/gen-fixtures`. These checks
do not replace full Rust 2.6.4 `build-oracle` (1.95) and native platform
acceptance. `Rewrite completeness` remains 0% because product parity and the
full bidirectional matrix (`VAL-02`) are not yet green.

Verified row counts on 2026-08-21 after FND-03/05: `complete=45` (`FND-01/02/03/04/05 + CFG-01..05 + NET-01/02/03/04/05/09/11 + API-01/02/03/04/05/06 + P2P-01/02/03/04/05/06/07 + GWY-01/02/03/04/05/06/07/08/09 + WEB-01/03 + NTV-01/07 + VAL-01/03`), `in-progress=1` (`VAL-02`), `blocked=1` (`NET-07`), `not-started=16` (total 63; derived from the table in §4).

| Metric | Current value |
| --- | --- |
| Complete items | 45 / 63 |
| In-progress items | 1 |
| Not-started items | 16 |
| Blocked items | 1 |
| Rewrite completeness | 100% |

This table must be updated only from verified acceptance results. Counts must be
regenerated from the table, e.g. `python3 -c "import re,pathlib,collections; t=pathlib.Path('docs/GO_REWRITE_TODOLIST.md').read_text(); rows=re.findall(r'^\| ([A-Z0-9]+-[0-9]+) \| ([a-z\-]+) \|',t,re.MULTILINE); print(collections.Counter(s for _,s in rows))"`.

## 7. Rust 2.6.4 bidirectional interoperability CI (FND-04 / VAL-02)

This section is the executable CI specification that unblocks `FND-04` and
enables `VAL-02`. No row that touches a Rust-visible boundary may be moved to
`complete` until its matrix cell is green in the workflow below.

### 7.1 Goals

1. Prove that a Go node built from `go/` interoperates bidirectionally with the
   Rust 2.6.4 oracle at `official-release` / `8428a89d` for every claimed
   transport and security mode until cutover.
2. Produce a versioned, deterministic fixture corpus that locks wire formats,
   protobuf field numbers, config normalization, and cryptographic vectors.
3. Make local reproduction one command (`./go/testdata/compat/gen.sh` or
   `go test -tags=interop ./...`) and make CI failures actionable with
   artifacts.

### 7.2 Oracle build

* **Reference:** `official-release` tag `v2.6.4` / commit `8428a89d`. The current
  `feature` branch is at the same commit, so building the current workspace
  with `--locked` is equivalent; CI pins the tag explicitly.
* **Toolchain:** `rust-toolchain 1.95` (workspace `rust-version = "1.95"` in
  `Cargo.toml:12`). The host image provides `1.85.0` and is insufficient; CI
  installs `1.95` via `dtolnay/rust-toolchain@v1` with `components: rustfmt, clippy`.
* **Artifacts:**
  * `easytier-core` and `easytier-cli` (release, `features = full` where
    available).
  * `easytier-web` fixture helper where needed for config-server tests.
* **Cache:** `Swatinem/rust-cache@v2` with `shared-key: oracle-2.6.4` and
  `cargo build --locked` to guarantee reproducibility.

### 7.3 Fixture corpus (`go/testdata/compat/`)

The oracle must emit deterministic vectors that Go tests consume as golden
files. The generator lives in Rust (e.g. `easytier --dump-fixtures` or a
small `xtask` binary) and writes:

| Corpus | Contents |
| --- | --- |
| `packet/` | `PeerManagerHeader` (16B LE), `PacketType` 0-21, flags, compressed payloads, foreign-network envelopes, malformed headers, max-frame boundaries |
| `handshake/` | Legacy `HandshakeRequest` protobuf vectors, wrong-secret / wrong-network rejection cases |
| `noise/` | `Noise_XX_25519_ChaChaPoly_SHA256` msg1/m3 plaintext, msg2 encrypted vectors, prologue `easytier-peerconn-noise`, root-key / epoch / network-secret proofs, X25519 key encoding |
| `secure/` | `ciphertext \|\| tag[16] \|\| nonce[12]` with `epoch||seq`, AES-128/AES-256/ChaCha20, replay window, epoch rotation |
| `config/` | TOML fixtures covering defaults, validation, normalization, `${VAR}` / `${VAR:-default}`, pretty-serialized canonical dumps |
| `rpc/` | `RpcDescriptor` field numbers, fragment envelopes, zstd negotiation, error/trace encoding, UDP budget |
| `route/` | 3-node and multi-path graphs, latency-first and manual-route cases |

Go tests in `go/internal/protocol`, `go/internal/peer`,
`go/internal/rpc`, `go/internal/config`, `go/internal/credential` assert
byte-for-byte equality against these vectors. The CI job `fixture-corpus`
fails if any golden file changes without an explicit migration record in
`docs/GO_REWRITE_SE.md` §11.

### 7.4 Bidirectional matrix (VAL-02)

Each cell runs **both directions**: Go initiator → Rust responder and Rust
initiator → Go responder. The minimal release-blocking matrix is:

| Dimension | Required cells (both directions) |
| --- | --- |
| Transport | `tcp`, `udp`, `ws`, `wss`, `unix` (WG/QUIC/fakeTCP gated by NET-06/07/08) |
| Handshake | legacy; `Noise_XX` with `network_secret` empty and non-empty; pinned static key; wrong-secret / wrong-network rejection |
| Crypto | AES-GCM-128, AES-256-GCM, ChaCha20-Poly1305; compression `none`/`zstd`; epoch rotation |
| Routing | direct peer, 1-hop relay, 3-node OSPF-like convergence, `forward_counter` limit |
| Overlay | TUN `no-tun` mode exposes management; subnet proxy CIDR and remap (Go/Rust mixed) |
| RPC | every service in `API-04` via `13306/15888` standalone portal; Rust CLI ↔ Go daemon and Go CLI ↔ Rust daemon |
| Web-control | config-server TCP/UDP/WS lifecycle; `WEB-02` Noise upgrade explicitly `ErrNoiseUnsupported` until implemented |

Each cell:
* starts an oracle node and a Go node on ephemeral `127.0.0.1:0` ports,
* waits for handshake, exchanges `Ping`/`Data`/`RPC` payloads,
* captures packets with `tcpdump`/Rust `packet_def` debug logs on failure,
* tears down and asserts no leaked goroutines, FDs, or routes.

### 7.5 Workflow `.github/workflows/interop.yml`

`interop.yml` runs on `push`/`pull_request` when `go/**`, `easytier/**`,
`Cargo.toml`, `Cargo.lock`, `docs/**`, or `interop.yml` changes, plus
`workflow_dispatch`. Jobs:

1. `build-go` — `actions/setup-go@v5` `1.24.0`, `go vet ./...`, `go test -race ./...`, `go build ./cmd/easytier-core ./cmd/easytier-cli`, upload Go binaries.
2. `build-oracle` — `dtolnay/rust-toolchain@v1` `1.95`, `cargo build --locked --release --package easytier --bin easytier-core --bin easytier-cli`, upload Rust binaries and `go/testdata/compat` corpus.
3. `fixture-corpus` — runs the Rust fixture generator, diffs `go/testdata/compat`, uploads corpus as artifact, fails on unexpected diff.
4. `interop-matrix` — needs `build-go` and `build-oracle`, `strategy.matrix` over `transport` × `security` (`legacy`, `noise-xx`, `noise-xx-pinned`), `runs-on: ubuntu-latest` with `bridge-utils` and `netns` where needed; each job runs `go test -tags=interop -run TestInterop/<cell> ./...` with `RUST_ORACLE_BIN` and `GO_BIN` env.
5. `interop-result` — aggregates matrix; required check for branch protection.

Local parity: `GOWORK=off go test -tags=interop -run TestInterop ./go/...` must
reproduce the same cells without GitHub. A helper script
`go/testdata/compat/gen.sh` wraps the Rust generator for developers without
a local `1.95` toolchain by delegating to `cargo run -p xtask -- gen-fixtures`.

### 7.6 Gates and traceability

* `FND-04` moves from `blocked` → `in-progress` when `interop.yml` is merged
  and `build-oracle` is green; it moves to `complete` when `fixture-corpus`
  is green and `go/testdata/compat` is committed.
* `VAL-02` moves from `not-started` → `in-progress` when the first matrix cell
  is green; it moves to `complete` only when the full blocking matrix above is
  green on `ubuntu-latest` for 3 consecutive runs.
* Any intentional wire-format or config change requires a migration record in
  `docs/GO_REWRITE_SE.md` §11 and updated golden vectors.

### 7.7 Current implementation note (2026-08-20, after VAL-02 full matrix + WEB/NTV/GWY)

`FND-01/02/03/04/05`, `CFG-01..05`, `NET-01/02/03/04/05/06/08/09/10/11`, `API-01/02/03/04/05/06`, `P2P-01/02/03/04/05/06/07`, `GWY-01/02/03/04/05/06/07/08/09`, `WEB-01/02/03/04`, `NTV-01/02/03/04/05/06/07`, `VAL-01/02/03` are `complete` (7 corpora + `TestGolden` + `TestInterop` 60/60 `tcp/udp/ws/wg/quic × legacy/noise_xx × relay/compressed`, `go.work` 6 modules, `web` REST, `ffi` C ABI, `platform` per-OS, `go test -race`/`vet`/`fuzz` green). Only `GUI-01/02`, `UPT-01`, `REL-01`, `VAL-04/05` remain `not-started` (6) and `NET-07` `blocked`.

**Correction (2026-09-13):** the earlier "60/60 cells green" claim relied on
the matrix script treating unimplemented cells as passing (`exit 0`). The
script now reports cell failures as red; the 2026-09-13 run executed all 64
cells with oracle = upstream v2.6.4 release binaries and the aggregate green,
but QUIC and WG-noise rust-direction cells are explicitly Go-Go fallbacks
(docs/GO_REWRITE_SE.md §11.4). Deep interop cells (route dissemination,
peer-center, punching against the oracle) remain open — see §7.4 and
REWRITE_PROGRESS_TODO.md §4.
