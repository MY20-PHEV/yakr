#!/usr/bin/env bash
# Deploy Charlie relay (yakr-relay) to a VPS via SSH + Docker.
#
# Usage:
#   VPS_HOST=user@203.0.113.10 ./scripts/deploy_charlie_vps.sh
#
# HTTPS (pairing-anchored TLS):
#   python scripts/generate_operator_relay_tls.py /path/to/charlie-operator-home
#   CHARLIE_TLS_DIR=/path/to/charlie-operator-home/relay-tls ./scripts/deploy_charlie_vps.sh
#
# Optional: CHARLIE_WRAP_SECRET, CHARLIE_PORT (default 8090), REMOTE_DIR

set -euo pipefail
cd "$(dirname "$0")/.."

VPS_HOST="${VPS_HOST:?set VPS_HOST e.g. user@203.0.113.10}"
CHARLIE_PORT="${CHARLIE_PORT:-8090}"
REMOTE_DIR="${REMOTE_DIR:-~/yakr-relay}"
CHARLIE_WRAP_SECRET="${CHARLIE_WRAP_SECRET:-}"
CHARLIE_TLS_DIR="${CHARLIE_TLS_DIR:-}"

if [[ -z "$CHARLIE_WRAP_SECRET" ]]; then
  CHARLIE_WRAP_SECRET="$(python3 - <<'PY'
import base64, hashlib
print(base64.urlsafe_b64encode(hashlib.sha256(b"yakr-demo-vps-charlie-wrap-v0").digest()).decode().rstrip("="))
PY
)"
fi

SCHEME=http
RELAY_TLS_ARGS=()
DOCKER_TLS_MOUNT=()
CURL_INSECURE=""
if [[ -n "$CHARLIE_TLS_DIR" ]]; then
  if [[ ! -f "$CHARLIE_TLS_DIR/endpoint.key.pem" || ! -f "$CHARLIE_TLS_DIR/endpoint.cert.pem" ]]; then
    echo "CHARLIE_TLS_DIR must contain endpoint.key.pem and endpoint.cert.pem" >&2
    exit 1
  fi
  SCHEME=https
  CURL_INSECURE=-k
  RELAY_TLS_ARGS=(--ssl-keyfile /tls/endpoint.key.pem --ssl-certfile /tls/endpoint.cert.pem)
  echo "Uploading TLS material to VPS…"
  ssh "$VPS_HOST" "mkdir -p ${REMOTE_DIR}/tls"
  scp -q "$CHARLIE_TLS_DIR/endpoint.key.pem" "$CHARLIE_TLS_DIR/endpoint.cert.pem" "${VPS_HOST}:${REMOTE_DIR}/tls/"
  DOCKER_TLS_MOUNT=(-v "${REMOTE_DIR}/tls:/tls:ro")
fi

IMAGE_TAG="yakr-relay:local"
echo "Building relay image…"
docker build -t "$IMAGE_TAG" .

echo "Saving image and copying to ${VPS_HOST}…"
docker save "$IMAGE_TAG" | ssh "$VPS_HOST" "docker load"

echo "Starting Charlie relay on port ${CHARLIE_PORT} (${SCHEME})…"
# shellcheck disable=SC2029
ssh "$VPS_HOST" docker rm -f yakr-charlie 2>/dev/null || true
# shellcheck disable=SC2029
ssh "$VPS_HOST" docker run -d \
  --name yakr-charlie \
  --restart unless-stopped \
  -p "${CHARLIE_PORT}:8080" \
  -v yakr-charlie-data:/data \
  "${DOCKER_TLS_MOUNT[@]}" \
  "$IMAGE_TAG" \
  yakr-relay serve \
    --host 0.0.0.0 \
    --port 8080 \
    --data-dir /data \
    --role both \
    --name charlie \
    --wrap-secret "$CHARLIE_WRAP_SECRET" \
    "${RELAY_TLS_ARGS[@]}"

sleep 2
# shellcheck disable=SC2029
ssh "$VPS_HOST" "curl -sf ${CURL_INSECURE} ${SCHEME}://127.0.0.1:${CHARLIE_PORT}/healthz"

VPS_IP="$(ssh "$VPS_HOST" 'curl -sf ifconfig.me 2>/dev/null || hostname -I | awk "{print \$1}"')"
echo ""
echo "Charlie relay is up."
echo "  Health:  ${SCHEME}://${VPS_IP}:${CHARLIE_PORT}/healthz"
echo "  Export for local demo:"
echo "    export CHARLIE_URL=${SCHEME}://${VPS_IP}:${CHARLIE_PORT}"
echo "    export CHARLIE_WRAP_SECRET=${CHARLIE_WRAP_SECRET}"
if [[ -n "$CHARLIE_TLS_DIR" ]]; then
  echo "    # SPKI pin: $(cat "$CHARLIE_TLS_DIR/spki_sha256.hex" 2>/dev/null || echo see relay-tls/spki_sha256.hex)"
fi
echo "    ./scripts/demo_vps_charlie_relay.sh"
