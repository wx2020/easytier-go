# Release Engineering — Artifact Naming, Versioning, Reproducible Builds, SBOM, Checksums, Signatures, Provenance (FND-05)

> Governs Go rewrite artifacts (`go/`) parity with Rust 2.6.4 distribution.
> Reference: `docs/GO_REWRITE_TODOLIST.md` §5 (target matrix), `docs/GO_REWRITE_SE.md` §11.2.

## 1. Semantic versioning

Go follows **Rust semantic versioning** at `2.6.4`:

* Version source of truth: `VERSION` at repo root (currently `2.6.4`) and `Cargo.toml` `[package] version = "2.6.4"`.
* Git tags: `v2.6.4` (annotated). `go-release.yml` derives `VERSION` from `git describe --tags` or `GITHUB_REF_NAME` with leading `v` stripped for ldflags.
* Binary `--version`: both `easytier-core` and `easytier-cli` embed `version` via

  ```bash
  go build -trimpath -ldflags "-s -w -buildid= -X main.version=v${VERSION} -X main.commit=$(git rev-parse HEAD)"
  ```

  `var version = "0.0.0-dev"` in `go/cmd/easytier-core/main.go` and `go/cmd/easytier-cli/main.go` is overridden; fallback is `0.0.0-dev` for local builds. `easytier-cli --version` and `easytier-core --version` print `easytier-core v2.6.4 (go rewrite)` style.
* Pre-release/build metadata follows SemVer (`2.6.5-rc1`, `2.6.4+go1`). No API break without minor bump.

## 2. Artifact naming

Naming preserves the Rust distribution contract (`core.yml` `ARTIFACT_NAME`) while making Go artifacts self-descriptive. All archives are **reproducible tar.gz or zip with `SOURCE_DATE_EPOCH`** and contain `easytier-core` / `easytier-cli` plus SBOM/checksums.

### 2.1 Core artifacts (per target matrix `GO_REWRITE_TODOLIST.md` §5)

| Rust `TARGET` | `ARTIFACT_NAME` (Rust) | Go `GOOS/GOARCH` | Go archive name |
|---|---|---|---|
| `x86_64-unknown-linux-musl` | `linux-x86_64` | `linux/amd64` | `easytier-go-v2.6.4-linux-amd64.tar.gz` |
| `aarch64-unknown-linux-musl` | `linux-aarch64` | `linux/arm64` | `easytier-go-v2.6.4-linux-arm64.tar.gz` |
| `riscv64gc-unknown-linux-musl` | `linux-riscv64` | `linux/riscv64` | `easytier-go-v2.6.4-linux-riscv64.tar.gz` |
| `loongarch64-unknown-linux-musl` | `linux-loongarch64` | `linux/loong64` | `easytier-go-v2.6.4-linux-loong64.tar.gz` |
| `armv7-unknown-linux-musleabihf` | `linux-armv7hf` | `linux/arm` `GOARM=7` (hard float) | `easytier-go-v2.6.4-linux-armv7hf.tar.gz` |
| `armv7-unknown-linux-musleabi` | `linux-armv7` | `linux/arm` `GOARM=7` (soft) | `easytier-go-v2.6.4-linux-armv7.tar.gz` |
| `arm-unknown-linux-musleabihf` | `linux-armhf` | `linux/arm` `GOARM=6` (hard) | `easytier-go-v2.6.4-linux-armhf.tar.gz` |
| `arm-unknown-linux-musleabi` | `linux-arm` | `linux/arm` `GOARM=6` (soft) | `easytier-go-v2.6.4-linux-arm.tar.gz` |
| `mips-unknown-linux-musl` | `linux-mips` | `linux/mips` | `easytier-go-v2.6.4-linux-mips.tar.gz` |
| `mipsel-unknown-linux-musl` | `linux-mipsel` | `linux/mipsle` | `easytier-go-v2.6.4-linux-mipsle.tar.gz` |
| `x86_64-unknown-freebsd` | `freebsd-13.2-x86_64` | `freebsd/amd64` | `easytier-go-v2.6.4-freebsd-amd64.tar.gz` |
| `x86_64-apple-darwin` | `macos-x86_64` | `darwin/amd64` | `easytier-go-v2.6.4-darwin-amd64.tar.gz` |
| `aarch64-apple-darwin` | `macos-aarch64` | `darwin/arm64` | `easytier-go-v2.6.4-darwin-arm64.tar.gz` |
| `x86_64-pc-windows-msvc` | `windows-x86_64` | `windows/amd64` | `easytier-go-v2.6.4-windows-amd64.zip` |
| `i686-pc-windows-msvc` | `windows-i686` | `windows/386` | `easytier-go-v2.6.4-windows-386.zip` |
| `aarch64-pc-windows-msvc` | `windows-arm64` | `windows/arm64` | `easytier-go-v2.6.4-windows-arm64.zip` |

Archive contents (linux/darwin/freebsd `tar.gz`, windows `zip`):

```
easytier-core            # or easytier-core.exe on windows
easytier-cli             # or easytier-cli.exe
README.md
LICENSE
LICENSES/LGPL-3.0-only.txt
sbom.spdx.json           # per-artifact SBOM (also aggregated sbom.spdx.json)
sbom.cyclonedx.json      # optional CycloneDX
SHA256SUMS               # per-file checksums (inside archive + top-level)
```

Naming pattern:

```
easytier-go-v${VERSION}-{goos}-{goarch}[{goarm-variant}].{tar.gz|zip}
easytier-core-v${VERSION}-{goos}-{goarch}
easytier-cli-v${VERSION}-{goos}-{goarch}
```

Example: `easytier-go-v2.6.4-linux-amd64.tar.gz` containing `easytier-core` and `easytier-cli` built with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 -trimpath`.

### 2.2 Extended surfaces

* **Docker:** `linux/amd64`, `linux/arm64`, `linux/arm/v7`, `linux/arm/v6`, `linux/riscv64` — tags `easytier/easytier-go:v2.6.4` and `easytier/easytier-go:latest`, multi-arch manifest via `docker/buildx`.
* **Magisk:** `Easytier-Magisk-v2.6.4.zip` (reuses `easytier-magisk` layout, populated from `linux-arm64` binaries).
* **FFI/JNI:** versioned headers `easytier-ffi-v2.6.4.tar.gz` (`ffi/easytier.h`).

## 3. Reproducible builds

Reproducibility is enforced both locally (`script/reproducible-build.sh`) and in CI (`.github/workflows/go-release.yml`).

* **Toolchain pin:** `go 1.24.0` (`go.work` / `go/*/go.mod`, `actions/setup-go@v5` `1.24.0`, `golang-1.24-go` 1.24.4 host). Verify with `go version`.
* **Flags:**

  ```bash
  export CGO_ENABLED=0
  export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
  export GOFLAGS="-trimpath"
  go build -trimpath -ldflags "-s -w -buildid= -X main.version=v${VERSION}" \
    -o easytier-core ./cmd/easytier-core
  go build -trimpath -ldflags "-s -w -buildid= -X main.version=v${VERSION}" \
    -o easytier-cli ./cmd/easytier-cli
  ```

  * `-trimpath` removes filesystem paths, `-buildid=` empties build ID, `-s -w` strips debug.
  * `SOURCE_DATE_EPOCH` normalizes archive mtimes (`tar --sort-name --mtime=@$SOURCE_DATE_EPOCH --owner=0 --group=0`).
  * Host `GOPATH` and `GOCACHE` do not leak (`GOWORK=off` per-module builds).
* **Verification:** rebuilding the same tag on a clean runner yields byte-identical binaries; `sha256sum` diff must be empty. `script/reproducible-build.sh --verify` builds twice.

## 4. SBOM

* **Tool:** `anchore/sbom-action` (syft) or `syft` directly. Installed via `anchore/sbom-action@v0` or `go install github.com/anchore/syft@latest`.
* **Generation:**

  ```bash
  syft packages dir:. -o spdx-json=sbom.spdx.json
  syft packages dir:. -o cyclonedx-json=sbom.cyclonedx.json
  # per-artifact variant:
  syft easytier-core -o spdx-json=sbom.easytier-core.spdx.json
  ```

  SBOM includes all `go list -m all` modules plus container layers. CycloneDX is optional for GUI ingestion.
* ** CI:** `go-release.yml` runs `anchore/sbom-action` after build and uploads SBOM artifacts; `govulncheck ./...` must be clean (see `VAL_03_COVERAGE.md` §3.5).
* **Distribution:** `sbom.spdx.json` sits alongside archives and inside each archive.

## 5. Checksums

* Every artifact file has a `SHA256SUMS` entry:

  ```bash
  sha256sum easytier-go-v2.6.4-* > SHA256SUMS
  sha256sum -c SHA256SUMS   # verification step in release.yml
  ```

* Individual `*.sha256` sidecars are also emitted (`easytier-go-v2.6.4-linux-amd64.tar.gz.sha256`).
* Checksums are uploaded as release assets and as `dist/*.sha256`.

## 6. Signatures

Two complementary mechanisms (at least one must verify for a release):

* **cosign keyless (preferred, OIDC via GitHub → Fulcio/Rekor):**

  ```bash
  cosign sign-blob --yes --output-certificate cert.pem --output-signature SHA256SUMS.sig SHA256SUMS
  cosign verify-blob --cert cert.pem --signature SHA256SUMS.sig SHA256SUMS \
    --certificate-identity-regexp "https://github.com/EasyTier/EasyTier/.github/workflows/go-release.yml@refs/tags/v.*"
  ```

  Workflow uses `sigstore/cosign-installer@v3` and `actions/attest-build-provenance`.

* **GPG fallback:** if `GPG_PRIVATE_KEY` secret is set,

  ```bash
  gpg --armor --detach-sign SHA256SUMS  # yields SHA256SUMS.asc
  gpg --verify SHA256SUMS.asc SHA256SUMS
  ```

* All `*.sig`/`*.asc`/`*.pem` are published beside `SHA256SUMS`.

## 7. Provenance (SLSA)

* **SLSA Level 3** via `slsa-framework/slsa-github-generator`:

  ```yaml
  - uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
  ```

  Alternatively `actions/attest-build-provenance@v1` (Sigstore) is used per build job:

  ```yaml
  - uses: actions/attest-build-provenance@v1
    with:
      subject-path: "dist/*"
  ```

  Provenance (`*.intoto.jsonl`) binds `subject` digests (SHA256 of each artifact) to source commit, builder (`go-release.yml`), and build parameters.

## 8. Local reproduction

```bash
# one-shot reproducible release
VERSION=$(cat VERSION) ./script/reproducible-build.sh --version v2.6.4 --out dist/

# verify existing dist against rebuild
./script/reproducible-build.sh --verify

# individual steps
go vet ./... && go test -race ./...
syft packages dir:. -o spdx-json=sbom.spdx.json
sha256sum dist/* > dist/SHA256SUMS
cosign sign-blob --yes --output-signature dist/SHA256SUMS.sig dist/SHA256SUMS
```

## 9. CI pipeline

* `.github/workflows/go.yml`: PR/branch gate — `gofmt`, `go vet`, `go test -race`, native cross build.
* `.github/workflows/go-release.yml`: tag/release pipeline — reproducible matrix build → SBOM → SHA256 → cosign + attest → SLSA provenance → GitHub Release (draft) + artifact upload.
* `.github/workflows/interop.yml`: oracle build + fixture parity (blocks FND-04/VAL-02).
* `.github/workflows/release.yml`: existing Rust aggregation workflow reused for unified GitHub Release (Go assets merged alongside Rust `easytier-*` zips).

## 10. Security contact

Vulnerability reports use the same `govulncheck` DB; SBOM regressions fail the release job before signing. See `VAL_01_03_COVERAGE.md` for scan results.
