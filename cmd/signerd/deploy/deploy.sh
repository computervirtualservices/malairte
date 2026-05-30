#!/usr/bin/env bash
#
# Build and install signerd on this host. Run as root from the malairte source
# checkout (default /opt/malairted-src):
#
#   sudo ./cmd/signerd/deploy/deploy.sh
#
# Idempotent and safe:
#   - never overwrites an existing /etc/signerd/env (your secrets)
#   - does NOT start the service — you must fill in the env (SIGNER_TOKEN,
#     MLRT_ACCOUNT_XPUB) first, then `systemctl enable --now signerd`.
set -euo pipefail

SRC_DIR="${SRC_DIR:-/opt/malairted-src}"
BIN=/usr/local/bin/signerd
ENV_DIR=/etc/signerd
ENV_FILE="$ENV_DIR/env"
UNIT=/etc/systemd/system/signerd.service
SVC_USER=signer

if [ "$(id -u)" -ne 0 ]; then
  echo "error: run as root" >&2
  exit 1
fi

echo "==> Building signerd from $SRC_DIR"
cd "$SRC_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN" ./cmd/signerd

echo "==> Ensuring service user '$SVC_USER'"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$SVC_USER"

echo "==> Installing env dir + template"
install -d -m 0750 -o root -g "$SVC_USER" "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  install -m 0640 -o root -g "$SVC_USER" "$SRC_DIR/cmd/signerd/deploy/env.example" "$ENV_FILE"
  echo "    created $ENV_FILE from template — EDIT IT before starting."
else
  echo "    $ENV_FILE already exists — left untouched."
fi

echo "==> Installing systemd unit"
install -m 0644 "$SRC_DIR/cmd/signerd/deploy/signerd.service" "$UNIT"
systemctl daemon-reload

cat <<'NEXT'
==> Done. Next steps:
  1) Edit /etc/signerd/env  (SIGNER_TOKEN, MLRT_ACCOUNT_XPUB, self-test vars)
  2) systemctl enable --now signerd
  3) systemctl status signerd        # should be active (running)
  4) curl -s -H "Authorization: Bearer $SIGNER_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"chain":"MLRT","index":1}' \
        http://127.0.0.1:8088/v1/derive
NEXT
