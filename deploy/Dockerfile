# Multi-platform OCI image for kgateway
# Supports: linux/amd64, linux/arm64, darwin/arm64
#
# Usage:
#   docker buildx build --platform linux/amd64,linux/arm64,darwin/arm64 \
#     -t ghcr.io/kense-labs/kgateway:latest -f deploy/Dockerfile --push .
#
# Note: darwin/arm64 is a macOS binary for Docker Desktop on Apple Silicon.
#       For native macOS, use Homebrew: brew install kense-labs/tap/kgateway

# ── Linux: Alpine-based minimal image ────────────────────────────────────────────
FROM alpine:3 AS base
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 gateway && adduser -S -u 10001 gateway -G gateway && \
    mkdir -p /var/lib/kgateway && chown gateway:gateway /var/lib/kgateway

# ── Linux amd64 ────────────────────────────────────────────────────────────────
FROM base AS linux-amd64
COPY dist/kgateway /usr/local/bin/kgateway
USER gateway
ENTRYPOINT ["kgateway"]

# ── Linux arm64 ────────────────────────────────────────────────────────────────
FROM base AS linux-arm64
COPY dist/kgateway /usr/local/bin/kgateway
USER gateway
ENTRYPOINT ["kgateway"]

# ── macOS arm64 (Apple Silicon) ───────────────────────────────────────────────
# Packaged as standalone binary for Docker Desktop on Apple Silicon
FROM scratch AS darwin-arm64
COPY dist/kgateway /kgateway
ENTRYPOINT ["/kgateway"]
