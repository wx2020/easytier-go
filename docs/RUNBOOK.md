# EasyTier Go 2.6.4 — Operational Runbook (VAL-05)

> Release candidate: **v2.6.4** (Go rewrite) — parity with Rust 2.6.4 (`official-release` / `8428a89d`)
> Workspace: `go/` (core + CLI), `go/web` (control-plane), `go/ffi` (C ABI), `go/jni` (Android), `go/platform` (service adapters), `go/uptime` (monitor)
> Toolchain: Go 1.24.4 (`/usr/lib/go-1.24/bin/go`, `go.work` `1.24.0`, `actions/setup-go@v5` `1.24.0`), `protoc` 3.21.12, Node 20/pnpm 9.2, Android NDK 26.1, Rust 1.95 (oracle only)

## 1. Overview

This runbook governs **cutover** from the Rust 2.6.4 distribution to the Go 2.6.4 distribution and continued operation. It covers install, **upgrade**, **rollback**, **persisted-config**, **database**, and **mixed-version** deployments (VAL-04), plus the **release candidate**, **independent review**, and **Rust removal** gates (VAL-05).

The Go distribution provides every shipped product on the target matrix (`GO_REWRITE_TODOLIST.md` §5): `easytier-core`, `easytier-cli`, FFI (`easytier.h`), JNI (`libeasytier_jni.so` per ABI), web control-plane, Magisk module, OHOS HAR, Docker images, and GUI bundles. No runtime Rust core is shipped in Go artifacts.

## 2. Versioning and provenance (FND-05 / VAL-05)

- Source of truth: `VERSION` at repo root (`2.6.4`) and `Cargo.toml` `[package] version = "2.6.4"`.
- Git tag: `v2.6.4` (annotated). CI `go-release.yml` derives `VERSION` from `git describe --tags` or `GITHUB_REF_NAME` (`v` stripped) for `ldflags`.
- Binaries embed version:

  ```bash
  go build -trimpath -ldflags "-s -w -buildid= -X main.version=v2.6.4 -X main.commit=$(git rev-parse HEAD)" \
    -o easytier-core ./cmd/easytier-core
  go build -trimpath -ldflags "-s -w -buildid= -X main.version=v2.6.4 -X main.commit=$(git rev-parse HEAD)" \
    -o easytier-cli ./cmd/easytier-cli
  easytier-core --version  # -> easytier-core v2.6.4 (go rewrite)
  easytier-cli --version   # -> easytier-cli v2.6.4 (go rewrite)
  ```

- Reproducible builds: `CGO_ENABLED=0`, `-trimpath`, `SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)`, `tar --sort=name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0`.
- Every artifact ships with `sbom.spdx.json` (syft via `anchore/sbom-action`), `SHA256SUMS` (`sha256sum -c SHA256SUMS`), `SHA256SUMS.sig`/`SHA256SUMS.pem` (cosign keyless OIDC via Fulcio/Rekor), and SLSA provenance (`actions/attest-build-provenance`). See `docs/RELEASE.md`.

Verification:

```bash
VERSION=$(cat VERSION) ./script/reproducible-build.sh --version v2.6.4 --out dist/
sha256sum -c dist/SHA256SUMS
cosign verify-blob --certificate SHA256SUMS.pem --signature SHA256SUMS.sig \
  --certificate-identity-regexp "https://github.com/EasyTier/EasyTier/.github/workflows/go-release.yml@.*" \
  SHA256SUMS
```

## 3. Prerequisites

- **Config compatibility:** Go accepts all Rust 2.6.4 TOML fields, CLI flags, env mappings (`ET_*`), and `${VAR}`/`${VAR:-default}` expansion. Expanded configs are automatically marked `READ_ONLY|NO_DELETE` and are not persistable via management APIs — same as Rust.
- **Identity digest:** `protocol.GenerateDigestFromStrings` is byte-identical to Rust's `generate_digest_from_str` (SipHash-1-3, zero keys). Portal keys/WG configs are deterministic.
- **Backup required:** Before any upgrade, snapshot:
  - All TOML files under `--config-dir` (default `/etc/easytier` on Linux) and explicit `--config-file` paths.
  - Web SQLite DB (default `easytier-web.db` under `DataDir`, or `:memory:` fallback). Copy the file or `sqlite3 easytier-web.db .dump > backup.sql`.

## 4. Installation (fresh)

```bash
# Linux (musl) — example
curl -LO https://github.com/EasyTier/EasyTier/releases/download/v2.6.4/easytier-go-v2.6.4-linux-amd64.tar.gz
curl -LO https://github.com/EasyTier/EasyTier/releases/download/v2.6.4/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar -xzf easytier-go-v2.6.4-linux-amd64.tar.gz
sudo install -m 755 easytier-core easytier-cli /usr/local/bin/

# Docker
docker pull easytier/easytier-go:v2.6.4
docker run --cap-add=NET_ADMIN --device /dev/net/tun easytier/easytier-go:v2.6.4 \
  --network-name default --network-secret "" --listeners tcp://0.0.0.0:11010
```

Service managers (`systemd`, `launchd`, `rc.d`, Windows service) are handled via `go/internal/platform` and `go/platform` dry-run planners. Verify with `go test -run TestGwy02` style planner tests before privileged apply.

## 5. Upgrade — Rust 2.6.4 → Go 2.6.4 (VAL-04)

Upgrade is **in-place** and **without data loss**. Go reads all Rust-persisted TOML and SQLite files.

### 5.1 Pre-flight

```bash
# 1. Verify Rust installation version
easytier-core --version          # Rust 2.6.4
cat /etc/easytier/*.toml         # record instance_name / instance_id

# 2. Backup (mandatory)
sudo cp -a /etc/easytier /etc/easytier.bak.$(date +%F)
# web DB: stop web, then copy
sudo systemctl stop easytier-web || true
cp /var/lib/easytier/easytier-web.db ~/easytier-web.db.bak.$(date +%F)

# 3. Validate configs with Go (dry-run)
go run ./go/cmd/easytier-core --check-config --config-dir /etc/easytier
# Or via reproducible binary:
./dist/easytier-core --check-config --config-dir /etc/easytier
```

### 5.2 Upgrade steps (single host)

```bash
# 1. Stop Rust core (systemd example)
sudo systemctl stop easytier

# 2. Install Go binary (see §4) — keep Rust binary as /usr/local/bin/easytier-core.rust.bak
sudo mv /usr/local/bin/easytier-core /usr/local/bin/easytier-core.rust.bak
sudo install -m 755 ./dist/easytier-core /usr/local/bin/easytier-core

# 3. Start Go core with same config-dir and rpc-portal
sudo systemctl start easytier
# Verify:
easytier-core --version          # -> v2.6.4 (go rewrite)
easytier-cli --rpc-portal 127.0.0.1:15888 instance list
easytier-cli peer list
# Check persisted-config permissions:
# - Files whose stem equals instance_id are DELETABLE (remote deletable)
# - Other files and ${VAR}-expanded files are READ_ONLY|NO_DELETE
# See go/internal/config/migration_test.go: TestPersistedConfigOnUpgrade

# 4. Web control-plane (if used)
sudo systemctl stop easytier-web
# Go web migrates SQLite automatically: 001 -> 002 (unique index) -> 003 (source column)
sudo install -m 755 ./dist/easytier-web /usr/local/bin/easytier-web  # or go run ./go/web
sudo systemctl start easytier-web
# Verify migrations:
# - migrationsVersion == 3, append-only, idempotent (go/web/migration_test.go)
# - Existing users/groups/permissions and user_running_network_configs rows preserved
# - New column source defaults to 'user' (legacy rows become 'legacy' then 'user' on Go)
```

### 5.3 Upgrade steps (fleet)

1. Upgrade **relays/seed peers first**, then edges. Go and Rust interoperate bidirectionally for `tcp/udp/ws/wss` × `legacy/Noise_XX` × `Relay` (VAL-02 matrix). Mixed-version clusters are explicitly supported during rollout.
2. Keep at least one Rust seed until last edge is upgraded, then upgrade seeds.
3. Monitor `go/internal/interop` + `go test -run TestInterop` cells (both directions) for the claimed transports.

### 5.4 Post-upgrade validation

```bash
# Config round-trip idempotency (deterministic)
go test -run TestUpgradeFromRustToGo ./internal/upgrade -count=1
go test -run TestUpgradeIsDeterministic ./internal/upgrade -count=1

# Database
go test -run TestDatabaseUpgradePreservesData ./web -count=1

# Mixed-version (digest, endpoint, header)
go test -run TestMixedVersion ./internal/upgrade -count=1

# Golden vectors (wire, handshake, digest, secure, config, rpc, route, wg)
go test -run TestGolden ./... -count=1

# Service
easytier-cli instance status
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/api/v1/sessions
```

## 6. Rollback — Go 2.6.4 → Rust 2.6.4 (VAL-04)

Rollback is **safe**: Go's canonical dump (`Config.Dump()`) emits only Rust-known keys and omits defaults, so Rust can parse Go-persisted files.

```bash
# 1. Stop Go
sudo systemctl stop easytier

# 2. Restore Rust binary
sudo mv /usr/local/bin/easytier-core.rust.bak /usr/local/bin/easytier-core

# 3. Restore configs from backup if any manual edits were made via Go management API
# Go's Dump is byte-identical on repeated runs (deterministic); compare:
sudo cp -a /etc/easytier.bak.$(date +%F)/* /etc/easytier/

# 4. Restore web DB backup (if web was upgraded)
sudo systemctl stop easytier-web
cp ~/easytier-web.db.bak.$(date +%F) /var/lib/easytier/easytier-web.db
# Rust will see source column (added by Go) as extra column; SQLite ignores unknown
# columns when Rust's older schema queries explicit columns, so no loss.
# Alternatively, run down migrations: 003 (drop source) -> 002 (recreate unique index)

# 5. Start Rust
sudo systemctl start easytier
easytier-core --version  # Rust 2.6.4
go test -run TestRollback ./internal/upgrade -count=1 -v  # validates file still parseable
```

Determinism: repeated rollback (`Dump` → `Load` → `Dump`) yields byte-identical TOML (verified by `TestRollbackIsDeterministic`).

## 7. Persisted-config contract (VAL-04)

Go preserves Rust's `ConfigFileControl` semantics:

| Source | Permission | Behavior |
|---|---|---|
| `instance_id.toml` under `--config-dir` where filename stem == `instance_id` | `DELETABLE` (no flags) | Remote `config delete` allowed; file can be removed via management API |
| Other `*.toml` under `--config-dir` | `NO_DELETE` | Not deletable remotely |
| File with `${VAR}` expansion | `READ_ONLY|NO_DELETE` | Cannot be persisted/overwritten via management API (secret safety) |
| Read-only file on FS (`chmod 444`) | `READ_ONLY|NO_DELETE` | Same protection |
| `-` (stdin) | `STATIC_CONFIG` (`READ_ONLY|NO_DELETE`) | Never persistable |

Ordering is deterministic: directory entries are sorted, explicit `--config-file` first then sorted directory files.

## 8. Database contract (VAL-04)

Web DB (`go/web`) uses 3 migrations (SQLite, append-only, idempotent):

1. `001 init` — `users`, `groups`, `permissions`, `users_groups`, `groups_permissions`, `user_running_network_configs`, `tower_sessions` + seed `user`/`admin` (argon2).
2. `002 scope_network_config_unique` — scoped unique index on `(user_id, device_id, network_instance_id)` (replaces global unique on `network_instance_id`).
3. `003 add_network_config_source` — `source TEXT NOT NULL DEFAULT 'user'` (legacy rows filled with `'legacy'` then normalized).

Go's in-memory `store` mirrors this and is tested in `go/web/migration_test.go`:

- `TestMigrationsVersionIsThreeAndAppendOnly`
- `TestDatabaseUpgradePreservesData` (v1 → v3 without loss)
- `TestDatabaseUpgradeIdempotent` (re-apply no-ops)
- `TestDatabaseDowngradePreservesLegacyData` (v3 → v2 keeps rows)
- `TestPersistedConfigDatabaseCrossCheck` (TOML `instance_id` ↔ DB `network_instance_id` correlation)

For real SQLite, run:

```bash
sqlite3 easytier-web.db "select name from sqlite_master where type='table';"
sqlite3 easytier-web.db "pragma index_list(user_running_network_configs);"
```

## 9. Mixed-version deployment (VAL-04)

Go and Rust interoperate bidirectionally for all claimed transports until cutover.

- **Network identity:** `GenerateDigestFromStrings(network_name, network_secret)` is identical (SipHash-1-3). Empty secret (credential nodes) yields distinct digest.
- **Endpoints:** `tcp/udp/ws/wss/wg/quic/faketcp` with implicit ports are allowed for `tcp/udp/ws/wss/wg/quic/faketcp` (IpScheme). `ring://` without port is rejected — matches Rust `validate_mapped_listener_url`.
- **Packet header:** 16B little-endian, `forward_counter` limit enforced before allocation, `COMPRESSED` tail `compressed_bytes || algo_u8(1=zstd)`, header length is original uncompressed length.
- **Handshake:** legacy protobuf `HandshakeRequest`, wrong-secret/wrong-network rejection, Noise XX/IK with prologue `easytier-peerconn-noise` (NET-09/10).
- **Routing:** OSPF-like, 3-node and multi-path convergence, `forward_counter` limit (P2P-05).
- **Management:** Custom RPC over TCP tunnel frames (`13306/15888`), source whitelist before dispatch, loopback default.

Test with both binaries:

```bash
# Terminal A (Rust)
RUST_ORACLE_BIN=/path/to/easytier-core-rust easytier-core --network-name mixed-net --network-secret s --listeners tcp://0.0.0.0:11010

# Terminal B (Go)
GO_BIN=./dist/easytier-core ./dist/easytier-core --network-name mixed-net --network-secret s --peers tcp://127.0.0.1:11010

# Verify
easytier-cli --rpc-portal 127.0.0.1:15888 peer list
go test -run TestMixedVersionDeployment ./internal/upgrade -v
go test -run TestGolden ./... -count=1
```

## 10. Independent review (VAL-05)

Before GA, an independent reviewer (not the Go author) must sign off on:

- [ ] `go vet ./...` empty, `go test -race ./...` green, `go test -fuzztime=2x` green (VAL-03), `govulncheck` clean.
- [ ] Fixture corpus `go/testdata/compat` byte-identical after `cargo run -p gen-fixtures` (FND-04) and `TestGolden` green.
- [ ] Interop matrix `interop.yml` green for 3 consecutive runs on `ubuntu-latest` (VAL-02).
- [ ] Upgrade/rollback/mixed-version tests green (`go test -run TestUpgrade ./internal/upgrade`, `./web` migration tests).
- [ ] No runtime Rust core in Go artifacts (`go/internal/upgrade.TestNoRustCoreInGoProducts` green, `CGO_ENABLED=0` for core, `go list -m all` SBOM checked, `dist/` archives contain only `easytier-core`/`easytier-cli` Go binaries).
- [ ] Reproducible build verified (`script/reproducible-build.sh --verify`).
- [ ] This runbook is accurate and executable on a fresh host.

Review record: add a signed note to `docs/INDEPENDENT_REVIEW.md` or the release PR referencing this checklist and the `v2.6.4` tag.

## 11. Rust removal (VAL-05)

Go products ship **no runtime Rust core**:

- Core binaries (`easytier-core`, `easytier-cli`) are built with `CGO_ENABLED=0` (pure Go). `go vet` and `go list -m all` show only Go modules (`flynn/noise`, `gorilla/websocket`, `pelletier/go-toml`, `klauspost/compress`, `x/crypto`, `x/sys`, `protobuf`).
- FFI (`go/ffi`) and JNI (`go/jni`) are the only `CGO_ENABLED=1` adapters; they implement the C ABI/Kotlin API **in Go** (`go/ffi/ffi.go` `//go:build cgo` with no Rust linkage). `TestNoRustCoreInGoProducts` walks `go/` and asserts no `exec.Command("cargo")`/`"rustc"` or `librust` at runtime and no stray `import "C"` outside `ffi/jni`.
- Docker, Magisk, OHOS, Android, GUI artifacts are assembled from Go builds only (see `go-release.yml` matrix + `script/reproducible-build.sh`).
- The Rust oracle remains in the repo for CI (`interop.yml` `build-oracle` with `rust-toolchain 1.95`) but is **not** included in `dist/` or published releases.

To verify after build:

```bash
file dist/easytier-core | grep -v "Rust"
strings dist/easytier-core | grep -i "rust.*1\.95" || echo "no Rust toolchain strings (expected)"
go vet ./... && go test -run TestNoRustCoreInGoProducts ./internal/upgrade -v
```

## 12. Operational procedures

### 12.1 Service lifecycle

```bash
# systemd
sudo systemctl status easytier
sudo journalctl -u easytier -f
sudo systemctl restart easytier
# logs: file_logger (dir /tmp/easytier, level info) + console_logger (warn) per config
```

Each instance runs under a context-bound supervisor; all sockets, TUN FDs, routes, DNS changes, mapping leases, and temp files have a close/rollback path. Multi-instance (`--config-dir`) lifecycle via `management.InstanceList/Start/Stop` is deterministic.

### 12.2 Monitoring

- **Metrics:** Prometheus scrape via management RPC `Stats`/`Prometheus` (see `internal/management`, `internal/stats`). Check `go/internal/stats` and `internal/webapi` auth before scrape.
- **Health:** `easytier-cli instance status`, `peer list`, `route list`, `connector list`, `acl stats`.

### 12.3 Backup

- **Config:** snapshot `--config-dir` before any `config set` or upgrade.
- **Web DB:** `sqlite3 easytier-web.db ".backup backup.db"` or file copy while web is stopped.
- **Restore:** copy back, `chown`, `systemctl start`.

### 12.4 Network / platform

- TUN, routes, DNS (systemd-resolved, registry, resolver), interface addressing (Linux netlink, Windows netsh/Wintun, macOS/FreeBSD ifconfig) are applied via `internal/platform` planners with dry-run (`Plan` + `Rollback`). Verify before privileged apply.
- NAT: STUN (`txt:stun.easytier.cn`), UPnP IGD/NAT-PMP (300s lease, 240s renewal), TCP hole-punching, UDP cone/symmetric/easy-symmetric.
- Public IPv6 provider and UDP broadcast relay are explicit flags.

## 13. Troubleshooting

| Symptom | Cause | Mitigation |
|---|---|---|
| `validate config "listeners are invalid"` on start | Mixed `ws://` without port or typo | Check `ParseEndpoint`/`ValidateMappedListenerURL`; allowed implicit ports for `tcp/udp/ws/wss/wg/quic/faketcp` only |
| `network_identity.network_name is required` | Empty TOML | Provide `[network_identity] network_name = "my-net"` |
| Management `401/403` | Missing Bearer token or source not in whitelist | Supply `Authorization: Bearer <token>` and add source CIDR to `whitelist` |
| Web `source` column missing after upgrade | Old DB backup restored without migration | Restart Go web; it auto-migrates to v3. Verify `sqlite3 db "pragma table_info(user_running_network_configs)"` contains `source` |
| `t.Skip: requires root or CAP_NET_ADMIN` | Privileged test on unprivileged host | Expected for `go/internal/platform/linux/tun_test.go`; use dry-run planner instead |

## 14. Security

- Secrets (`network_secret`, `local_private_key`) are redacted from logs/metrics/UI. Expanded configs are `READ_ONLY|NO_DELETE`.
- RPC portal defaults to `127.0.0.1:15888` with loopback whitelist; deny-by-default outside explicit CIDRs.
- Dependency scanning (`govulncheck`, `syft` SBOM) runs in `go-release.yml` `assemble` job. No critical/high vulns.

## 15. References

- `docs/GO_REWRITE_TODOLIST.md` §4.I (VAL-04/05), §7 (interop matrix), `docs/GO_REWRITE_SE.md` §4-§6, §8, §11
- `docs/RELEASE.md` (versioning, naming, reproducible builds, SBOM, checksums, cosign, provenance)
- `docs/CLEAN_ROOM.md` (oracle use, SPDX, REUSE)
- `docs/VAL_01_03_COVERAGE.md` (test layers, fuzz, race, hardening)

## 16. Release candidate checklist (v2.6.4)

- [ ] `VERSION` == `2.6.4`, `go/web` `Version == 2.6.4`, `easytier-core --version` prints `v2.6.4` (ldflags)
- [ ] `go vet ./...` and `go test -race ./...` green in `go/` (GOWORK=off); `go test ./...` green in `go/web` (workspace)
- [ ] `go test -run TestUpgrade|TestRollback|TestPersisted|TestDatabase|TestMixedVersion ./internal/upgrade` green, deterministic
- [ ] `go test -run TestMigrations ./web` green
- [ ] `TestNoRustCoreInGoProducts` green, `CGO_ENABLED=0` for core, no Rust strings in `dist/`
- [ ] Reproducible build verified (`--verify`), SBOM/checksums/signatures/provenance emitted
- [ ] Independent review signed (see §10)
- [ ] This runbook executed on a fresh VM/device for at least one target in §5 (e.g., `linux-amd64`)

Once all boxes are checked, publish `v2.6.4` (Go) as the **cutover** release. The Rust implementation remains the compatibility oracle until cutover; after cutover, Go is the source of truth and the clean-room constraint is superseded (SPDX/SBOM remain).

