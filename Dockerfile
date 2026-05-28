# --- Build Stage ---
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bypath ./cmd/bypath

# --- Runtime Stage ---
FROM alpine:3.19

RUN apk add --no-cache \
    iptables \
    ip6tables \
    ipset \
    iproute2 \
    firejail \
    curl \
    jq \
    ca-certificates

# Create app directory
WORKDIR /app

# Copy binary
COPY --from=builder /bypath /app/bypath

# Copy default config
COPY configs/default.yaml /app/configs/default.yaml

# Create data directories
RUN mkdir -p /app/data/profiles /app/data/ips /app/engines /app/logs

# Expose ports
EXPOSE 8080/tcp 53/udp 53/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/status || exit 1

# Run with NET_ADMIN capability (required for iptables/routing)
# docker run --cap-add=NET_ADMIN --net=host liberoute
ENTRYPOINT ["/app/bypath"]
CMD ["--config", "/app/configs/default.yaml"]
