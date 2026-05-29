# --- Build Stage ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VARIANT=lite
ARG BUILD_TAGS=""
ARG VERSION=2.1.0-dev

RUN CGO_ENABLED=0 GOOS=linux go build \
    ${BUILD_TAGS:+-tags $BUILD_TAGS} \
    -ldflags="-s -w -X github.com/liberoute/bypath/internal/build.Version=${VERSION} -X github.com/liberoute/bypath/internal/build.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /bypath ./cmd/bypath

# --- Runtime Stage ---
FROM alpine:3.20

RUN apk add --no-cache \
    iptables \
    ip6tables \
    iproute2 \
    curl \
    ca-certificates \
    && mkdir -p /app/data/profiles /app/data/tmp /app/engines /app/logs /app/configs

# Install sing-box
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) SB_ARCH="amd64" ;; \
        aarch64) SB_ARCH="arm64" ;; \
        armv7l) SB_ARCH="armv7" ;; \
        *) SB_ARCH="amd64" ;; \
    esac && \
    wget -qO /tmp/sing-box.tar.gz "https://github.com/SagerNet/sing-box/releases/download/v1.11.0/sing-box-1.11.0-linux-${SB_ARCH}.tar.gz" && \
    tar -xzf /tmp/sing-box.tar.gz -C /tmp && \
    mv /tmp/sing-box-*/sing-box /usr/local/bin/sing-box && \
    chmod +x /usr/local/bin/sing-box && \
    rm -rf /tmp/sing-box*

# Install tun2socks
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
        x86_64) T2S_ARCH="amd64" ;; \
        aarch64) T2S_ARCH="arm64" ;; \
        armv7l) T2S_ARCH="armv7" ;; \
        *) T2S_ARCH="amd64" ;; \
    esac && \
    wget -qO /usr/local/bin/tun2socks "https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-linux-${T2S_ARCH}" && \
    chmod +x /usr/local/bin/tun2socks

WORKDIR /app

# Copy binary and config
COPY --from=builder /bypath /app/bypath
COPY configs/default.yaml /app/configs/default.yaml

EXPOSE 8080/tcp 53/udp 53/tcp 2801/tcp

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:8080/api/v1/status || exit 1

# Requires: docker run --cap-add=NET_ADMIN --net=host
ENTRYPOINT ["/app/bypath"]
CMD ["run", "-c", "/app/configs/default.yaml"]
