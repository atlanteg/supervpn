# syntax=docker/dockerfile:1
# Multi-stage build: compile on golang image, run on minimal scratch.

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /supervpn-server ./cmd/supervpn-server

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM scratch

COPY --from=builder /supervpn-server /supervpn-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Default config location — mount a volume or bind-mount your server.toml here.
VOLUME ["/etc/supervpn"]

# UDP VPN port + TCP/TLS fallback + status API
EXPOSE 5555/udp 443/tcp 9090/tcp

ENTRYPOINT ["/supervpn-server", "-config", "/etc/supervpn/server.toml"]
