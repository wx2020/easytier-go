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
