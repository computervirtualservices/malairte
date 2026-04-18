#!/usr/bin/env bash
# start-devnet.sh — Launches a local Malairt devnet (single-node testnet with mining).
#
# Usage:
#   ./scripts/start-devnet.sh [--reset]
#
# Options:
#   --reset    Delete existing devnet data before starting (fresh chain)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BIN_DIR="$PROJECT_DIR/bin"
DATA_DIR="$PROJECT_DIR/data/devnet"

# Parse flags
RESET=false
for arg in "$@"; do
  case $arg in
    --reset)
      RESET=true
      ;;
    *)
      echo "Unknown flag: $arg"
      echo "Usage: $0 [--reset]"
      exit 1
      ;;
  esac
done

# Build if binaries don't exist
if [ ! -f "$BIN_DIR/malairted" ]; then
  echo "Building malairted..."
  cd "$PROJECT_DIR"
  go build -o "$BIN_DIR/malairted" ./cmd/malairted
  go build -o "$BIN_DIR/malairtcli" ./cmd/malairtcli
fi

# Reset devnet data if requested
if [ "$RESET" = true ]; then
  echo "Resetting devnet data at $DATA_DIR..."
  rm -rf "$DATA_DIR"
fi

mkdir -p "$DATA_DIR"

echo ""
echo "Starting Malairt devnet..."
echo "  Data dir: $DATA_DIR"
echo "  RPC:      http://127.0.0.1:19332"
echo "  P2P:      0.0.0.0:19333"
echo ""
echo "Try: $BIN_DIR/malairtcli --rpc http://127.0.0.1:19332 getinfo"
echo ""

exec "$BIN_DIR/malairted" \
  --network=testnet \
  --mine \
  --data-dir="$DATA_DIR" \
  --rpc-addr=127.0.0.1:19332 \
  --p2p-addr=0.0.0.0:19333 \
  --log-level=info
