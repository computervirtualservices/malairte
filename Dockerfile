# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy dependency manifest first.
# go.sum may not exist yet on a fresh clone — go mod tidy generates it.
COPY go.mod ./
COPY . .

# Download and verify modules, generating go.sum if absent
RUN go mod tidy

# Build both binaries — static, stripped, no CGO
RUN CGO_ENABLED=0 GOOS=linux go build \
        -a -installsuffix cgo \
        -ldflags="-s -w" \
        -o /bin/malairted ./cmd/malairted \
    && CGO_ENABLED=0 GOOS=linux go build \
        -a -installsuffix cgo \
        -ldflags="-s -w" \
        -o /bin/malairtcli ./cmd/malairtcli

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/malairted  /usr/local/bin/malairted
COPY --from=builder /bin/malairtcli /usr/local/bin/malairtcli

# P2P port
EXPOSE 9333
# RPC port
EXPOSE 9332

RUN mkdir -p /data

VOLUME ["/data"]

ENTRYPOINT ["malairted"]
CMD ["--data-dir=/data", "--network=mainnet"]
