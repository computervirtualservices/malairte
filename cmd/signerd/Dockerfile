# Build from the blockchain-app module root:
#   docker build -f cmd/signerd/Dockerfile -t coindock/signerd:dev .
#
# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod ./
COPY . .

RUN go mod tidy

# Static, stripped, no CGO.
RUN CGO_ENABLED=0 GOOS=linux go build \
        -a -installsuffix cgo \
        -ldflags="-s -w" \
        -o /bin/signerd ./cmd/signerd

# ── Stage 2: Minimal runtime image ───────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 signer

USER signer

# Private RPC port (bind to a private interface via SIGNER_BIND_ADDR).
EXPOSE 8088

COPY --from=builder /bin/signerd /usr/local/bin/signerd

# All config via env (see cmd/signerd/README.md). No secrets baked into the image.
ENTRYPOINT ["signerd"]
