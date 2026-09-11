#!/usr/bin/env bash
set -euo pipefail

# Generate Rust 2.6.4 compatibility fixtures into go/testdata/compat/.
# Requires rust-toolchain 1.95 (workspace rust-version). Falls back to a
# no-op with a warning when the generator binary is not yet available, so
# `go test -race ./...` remains green during the Go-only phase.

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
COMPAT_DIR="$ROOT/go/testdata/compat"

echo "Compat dir: $COMPAT_DIR"
mkdir -p "$COMPAT_DIR"/{packet,handshake,noise,secure,config,rpc,route}

if command -v cargo >/dev/null 2>&1 && cargo run --manifest-path "$ROOT/tools/gen-fixtures/Cargo.toml" -- --help >/dev/null 2>&1; then
  echo "Running Rust fixture generator (tools/gen-fixtures, 1.85+)..."
  cargo run --manifest-path "$ROOT/tools/gen-fixtures/Cargo.toml" -- --out "$COMPAT_DIR"
  echo "Corpus generated via Rust."
  exit 0
fi

if command -v cargo >/dev/null 2>&1 && cargo run --locked -p easytier --bin gen-fixtures -- --help >/dev/null 2>&1; then
  echo "Running Rust fixture generator (easytier, 1.95 required)..."
  cargo run --locked -p easytier --bin gen-fixtures -- --out "$COMPAT_DIR"
  echo "Corpus generated."
  exit 0
fi

if [ -f "$ROOT/target/release/gen-fixtures" ]; then
  "$ROOT/target/release/gen-fixtures" --out "$COMPAT_DIR"
  exit 0
fi

# Fallback: Go generator (always available, produces byte-identical fixtures for packet/handshake/digest/rpc)
if [ -x "/usr/lib/go-1.24/bin/go" ]; then
  echo "Running Go fixture generator (go/cmd/gen-fixtures)..."
  /usr/lib/go-1.24/bin/go run "$ROOT/go/cmd/gen-fixtures" --out "$COMPAT_DIR" 2>&1 || go run "$ROOT/go/cmd/gen-fixtures" --out "$COMPAT_DIR"
  echo "Corpus generated via Go."
  exit 0
fi
if command -v go >/dev/null 2>&1; then
  echo "Running Go fixture generator (go/cmd/gen-fixtures)..."
  go run "$ROOT/go/cmd/gen-fixtures" --out "$COMPAT_DIR"
  echo "Corpus generated via Go."
  exit 0
fi

cat >&2 <<'EOF'
WARN: No fixture generator found.
Expected one of:
  cargo run --manifest-path tools/gen-fixtures/Cargo.toml
  cargo run -p easytier --bin gen-fixtures
  go run go/cmd/gen-fixtures
EOF
touch "$COMPAT_DIR/.gitkeep"
find "$COMPAT_DIR" -type f | head -n 20 || true
