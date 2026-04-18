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
        -o /bin/malairte-node ./cmd/malairte-node \
    && CGO_ENABLED=0 GOOS=linux go build \
        -a -installsuffix cgo \
        -ldflags="-s -w" \
        -o /bin/malairte-cli ./cmd/malairte-cli

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /bin/malairte-node  /usr/local/bin/malairte-node
COPY --from=builder /bin/malairte-cli /usr/local/bin/malairte-cli

# P2P port
EXPOSE 9333
# RPC port
EXPOSE 9332

RUN mkdir -p /data

VOLUME ["/data"]

ENTRYPOINT ["malairte-node"]
CMD ["--data-dir=/data", "--network=mainnet"]
