#!/usr/bin/env bash
# ==============================================================================
# Standalone IPK builder for luci-app-easytier (aarch64 OpenWrt)
# Builds the Go core/CLI for linux/arm64 and packages the LuCI files.
# ==============================================================================
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${WORKDIR}/.." && pwd)"
if [ -d "${REPO_ROOT}/go" ]; then
	GO_SRC="${REPO_ROOT}/go"
elif [ -d "${WORKDIR}/../easytier-go/go" ]; then
	GO_SRC="$(cd "${WORKDIR}/../easytier-go/go" && pwd)"
else
	GO_SRC="${REPO_ROOT}/go"
fi

BUILDDIR="${WORKDIR}/build"
OUTPUTDIR="${WORKDIR}/bin"
PKG_NAME="luci-app-easytier"
PKG_VERSION="1.0.1"
PKG_RELEASE="1"
PKG_ARCH="aarch64_generic"
IPK_FILE="${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_${PKG_ARCH}.ipk"
GO_BIN="${GO_BIN:-go}"

echo "==> Building EasyTier Go for linux/arm64"
rm -rf "${BUILDDIR}" "${OUTPUTDIR}"
mkdir -p "${BUILDDIR}/data" "${BUILDDIR}/control" "${OUTPUTDIR}"
(
	cd "${GO_SRC}"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "${GO_BIN}" build -trimpath \
		-ldflags "-s -w -X main.version=v${PKG_VERSION}" \
		-o "${BUILDDIR}/easytier-core" ./cmd/easytier-core
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "${GO_BIN}" build -trimpath \
		-ldflags "-s -w -X main.version=v${PKG_VERSION}" \
		-o "${BUILDDIR}/easytier-cli" ./cmd/easytier-cli
)
cp "${BUILDDIR}/easytier-core" "${BUILDDIR}/easytier-cli" "${OUTPUTDIR}/"

echo "==> Staging data"
cp -a "${WORKDIR}/root/." "${BUILDDIR}/data/"
mkdir -p "${BUILDDIR}/data/usr/bin"
cp "${BUILDDIR}/easytier-core" "${BUILDDIR}/data/usr/bin/easytier-core"
cp "${BUILDDIR}/easytier-cli" "${BUILDDIR}/data/usr/bin/easytier-cli"
chmod 755 "${BUILDDIR}/data/usr/bin/easytier-core" \
	"${BUILDDIR}/data/usr/bin/easytier-cli" \
	"${BUILDDIR}/data/usr/bin/easytier-cgroup-exec" \
	"${BUILDDIR}/data/etc/init.d/easytier" \
	"${BUILDDIR}/data/www/cgi-bin/easytier-api"
chmod 600 "${BUILDDIR}/data/root/config/easytier/config.toml" 2>/dev/null || true

echo "==> Staging control"
cp "${WORKDIR}/control/control" "${BUILDDIR}/control/control"
cp "${WORKDIR}/control/postinst" "${BUILDDIR}/control/postinst"
cp "${WORKDIR}/control/postrm" "${BUILDDIR}/control/postrm"
chmod 755 "${BUILDDIR}/control/postinst" "${BUILDDIR}/control/postrm"
printf '2.0\n' > "${BUILDDIR}/debian-binary"

echo "==> Creating archives"
tar --numeric-owner --group=0 --owner=0 -czf "${BUILDDIR}/control.tar.gz" -C "${BUILDDIR}/control" .
tar --numeric-owner --group=0 --owner=0 -czf "${BUILDDIR}/data.tar.gz" -C "${BUILDDIR}/data" .
(cd "${BUILDDIR}" && tar --numeric-owner --group=0 --owner=0 -czf "${OUTPUTDIR}/${IPK_FILE}" debian-binary control.tar.gz data.tar.gz)

# Plain-file payload for apk-based systems (the F50 uses apk, not opkg).
tar --numeric-owner --group=0 --owner=0 -czf "${OUTPUTDIR}/${PKG_NAME}-files-${PKG_VERSION}.tar.gz" -C "${BUILDDIR}/data" .

echo "==> Build successful"
echo "    IPK:      ${OUTPUTDIR}/${IPK_FILE}"
echo "    Files:    ${OUTPUTDIR}/${PKG_NAME}-files-${PKG_VERSION}.tar.gz"
echo "    Binaries: ${OUTPUTDIR}/easytier-core ${OUTPUTDIR}/easytier-cli"
ls -lh "${OUTPUTDIR}"
