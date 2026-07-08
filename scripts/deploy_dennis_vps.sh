#!/usr/bin/env bash
# Deploy Dennis relay (yakr-relay) to a VPS via SSH + Docker.
#
# Usage:
#   VPS_HOST=user@203.0.113.10 ./scripts/deploy_dennis_vps.sh
#
# HTTPS:
#   python scripts/generate_operator_relay_tls.py /path/to/dennis-operator-home
#   DENNIS_TLS_DIR=/path/to/dennis-operator-home/relay-tls ./scripts/deploy_dennis_vps.sh

set -euo pipefail
cd "$(dirname "$0")/.."

export CHARLIE_PORT="${DENNIS_PORT:-8091}"
export CHARLIE_TLS_DIR="${DENNIS_TLS_DIR:-}"
export REMOTE_DIR="${DENNIS_REMOTE_DIR:-~/yakr-relay-dennis}"
export RELAY_CONTAINER="${DENNIS_CONTAINER:-yakr-dennis}"
export RELAY_NAME="dennis"
export RELAY_DATA_VOLUME="${DENNIS_DATA_VOLUME:-yakr-dennis-data}"
export URL_EXPORT_NAME="DENNIS_URL"

if [[ -z "${DENNIS_WRAP_SECRET:-}" ]]; then
  export CHARLIE_WRAP_SECRET="$(python3 - <<'PY'
import base64, hashlib
print(base64.urlsafe_b64encode(hashlib.sha256(b"yakr-demo-vps-dennis-wrap-v0").digest()).decode().rstrip("="))
PY
)"
else
  export CHARLIE_WRAP_SECRET="$DENNIS_WRAP_SECRET"
fi

exec ./scripts/deploy_charlie_vps.sh
