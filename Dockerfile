# kgateway OCI runtime image
#
# Multi-stage build that accepts a pre-built musl binary.
# Build context must contain the compiled Linux executable.
#
# Build example:
#   docker build -f Dockerfile \
#     --build-arg BINARY_NAME=kgateway \
#     -t kgateway:latest .

# ── Stage 1: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

ARG BINARY_NAME=kgateway
ENV BINARY_NAME=${BINARY_NAME}

# Install CA certificates for HTTPS and set timezone data
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 10001 gateway && adduser -S -u 10001 gateway -G gateway && \
    mkdir -p /var/lib/kgateway && chown gateway:gateway /var/lib/kgateway

WORKDIR /

# Copy the pre-built binary
COPY --chmod=755 ${BINARY_NAME} /usr/local/bin/kgateway

# Switch to non-root user
USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

EXPOSE 80 443 8080

ENTRYPOINT ["kgateway"]
