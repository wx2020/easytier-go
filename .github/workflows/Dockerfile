FROM alpine:latest AS base
FROM base AS builder

ARG TARGETPLATFORM

COPY . /tmp/artifacts
WORKDIR /tmp/output
# REL-01: Support both Rust (easytier-linux-*) and Go (easytier-go-v*-linux-*) layouts
RUN set -e; \
    ARTIFACT_ARCH=""; \
    GO_ART=""; \
    if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
        ARTIFACT_ARCH="x86_64"; GO_ART="linux-amd64"; \
    elif [ "$TARGETPLATFORM" = "linux/arm/v6" ]; then \
        ARTIFACT_ARCH="armhf"; GO_ART="linux-armhf"; \
    elif [ "$TARGETPLATFORM" = "linux/arm/v7" ]; then \
        ARTIFACT_ARCH="armv7hf"; GO_ART="linux-armv7hf"; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
        ARTIFACT_ARCH="aarch64"; GO_ART="linux-arm64"; \
    elif [ "$TARGETPLATFORM" = "linux/riscv64" ]; then \
        ARTIFACT_ARCH="riscv64"; GO_ART="linux-riscv64"; \
    else \
        echo "Unsupported architecture: $TARGETPLATFORM"; \
        exit 1; \
    fi; \
    echo "TARGETPLATFORM=$TARGETPLATFORM ARTIFACT_ARCH=$ARTIFACT_ARCH GO_ART=$GO_ART"; \
    # Prefer Go artifact (tar.gz flat) if present, fallback to Rust directory
    if ls /tmp/artifacts/easytier-go-*-${GO_ART}.tar.gz 1>/dev/null 2>&1; then \
        echo "Found Go artifact for $GO_ART"; \
        for f in /tmp/artifacts/easytier-go-*-${GO_ART}.tar.gz; do \
            tar -xzf "$f" -C /tmp/output/; \
        done; \
        # Go tar contains flat binaries; ensure they are at top
        if [ -f /tmp/output/easytier-core ]; then echo "Go binaries extracted"; fi; \
    elif [ -d "/tmp/artifacts/easytier-linux-${ARTIFACT_ARCH}" ]; then \
        echo "Found Rust artifact for $ARTIFACT_ARCH"; \
        cp /tmp/artifacts/easytier-linux-${ARTIFACT_ARCH}/* /tmp/output/; \
    elif ls /tmp/artifacts/easytier-linux-${ARTIFACT_ARCH}-*.zip 1>/dev/null 2>&1; then \
        echo "Found Rust zip for $ARTIFACT_ARCH"; \
        for f in /tmp/artifacts/easytier-linux-${ARTIFACT_ARCH}-*.zip; do unzip -o "$f" -d /tmp/output/; done; \
        # unzip may create subdir easytier-linux-*/ ; flatten
        if [ -d /tmp/output/easytier-linux-${ARTIFACT_ARCH} ]; then cp /tmp/output/easytier-linux-${ARTIFACT_ARCH}/* /tmp/output/ && rm -rf /tmp/output/easytier-linux-${ARTIFACT_ARCH}; fi; \
    else \
        echo "No artifact found for $TARGETPLATFORM ($ARTIFACT_ARCH/$GO_ART). Contents:"; ls -lR /tmp/artifacts; exit 1; \
    fi; \
    ls -lh /tmp/output/

FROM base

RUN apk add --no-cache tzdata tini
WORKDIR /app
COPY --from=builder --chmod=755 /tmp/output/* /usr/local/bin

# users can use "-e TZ=xxx" to adjust it
ENV TZ=Asia/Shanghai

# tcp
EXPOSE 11010/tcp
# udp
EXPOSE 11010/udp
# wg
EXPOSE 11011/udp
# ws
EXPOSE 11011/tcp
# wss
EXPOSE 11012/tcp

ENTRYPOINT ["/sbin/tini", "--", "easytier-core"]
