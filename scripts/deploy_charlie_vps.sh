#!/usr/bin/env bash
# Deploy Charlie relay (yakr-relay) to a VPS via SSH + Docker.
#
# Usage:
#   VPS_HOST=user@203.0.113.10 CHARLIE_PORT=8080 ./scripts/deploy_charlie_vps.sh
#
# Optional:
#   CHARLIE_WRAP_SECRET=base64url...   # must match local demo if using two-hop later
#   REMOTE_DIR=~/yakr-relay            # install path on VPS
#
# Opens TCP CHARLIE_PORT on the VPS (ensure cloud firewall allows it).

set -euo pipefail
cd "$(dirname "$0")/.."

VPS_HOST="${VPS_HOST:?set VPS_HOST e.g. user@203.0.113.10}"
CHARLIE_PORT="${CHARLIE_PORT:-8090}"
REMOTE_DIR="${REMOTE_DIR:-~/yakr-relay}"
CHARLIE_WRAP_SECRET="${CHARLIE_WRAP_SECRET:-}"

if [[ -z "$CHARLIE_WRAP_SECRET" ]]; then
  CHARLIE_WRAP_SECRET="$(python3 - <<'PY'
import base64, hashlib
print(base64.urlsafe_b64encode(hashlib.sha256(b"yakr-demo-vps-charlie-wrap-v0").digest()).decode().rstrip("="))
PY
)"
fi

IMAGE_TAG="yakr-relay:local"
echo "Building relay image…"
docker build -t "$IMAGE_TAG" .

echo "Saving image and copying to ${VPS_HOST}…"
docker save "$IMAGE_TAG" | ssh "$VPS_HOST" "docker load"

echo "Starting Charlie relay on port ${CHARLIE_PORT}…"
ssh "$VPS_HOST" bash -s <<EOF
set -euo pipefail
mkdir -p ${REMOTE_DIR}
docker rm -f yakr-charlie 2>/dev/null || true
docker run -d \\
  --name yakr-charlie \\
  --restart unless-stopped \\
  -p ${CHARLIE_PORT}:8080 \\
  -v yakr-charlie-data:/data \\
  ${IMAGE_TAG} \\
  yakr-relay serve \\
    --host 0.0.0.0 \\
    --port 8080 \\
    --data-dir /data \\
    --role both \\
    --name charlie \\
    --wrap-secret ${CHARLIE_WRAP_SECRET}
sleep 2
curl -sf "http://127.0.0.1:${CHARLIE_PORT}/healthz"
EOF

VPS_IP="$(ssh "$VPS_HOST" 'curl -sf ifconfig.me 2>/dev/null || hostname -I | awk "{print \$1}"')"
echo ""
echo "Charlie relay is up."
echo "  Health:  http://${VPS_IP}:${CHARLIE_PORT}/healthz"
echo "  Export for local demo:"
echo "    export CHARLIE_URL=http://${VPS_IP}:${CHARLIE_PORT}"
echo "    export CHARLIE_WRAP_SECRET=${CHARLIE_WRAP_SECRET}"
echo "    ./scripts/demo_vps_charlie_relay.sh"
