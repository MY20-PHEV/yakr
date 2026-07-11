#!/usr/bin/env bash
# End-to-end homelab / VPS relay deploy for a Yakr cell operator.
#
# Prerequisites: SSH to VPS, Docker on VPS, local `yakr` CLI, messaging identity initialized.
#
# Usage:
#   ./scripts/homelab_relay_deploy.sh \
#     --operator alice-ops \
#     --vps user@203.0.113.10 \
#     --public-url https://relay.example:8090
#
# Options:
#   --create          Run `yakr relay create` if bundle missing
#   --force-create    Recreate operator bundle (--force)
#   --skip-bootstrap  Skip capability bootstrap after deploy
#   --skip-status     Skip final status check

set -euo pipefail
cd "$(dirname "$0")/.."

OPERATOR=""
VPS_HOST=""
PUBLIC_URL=""
HOST_PORT=8090
DO_CREATE=0
FORCE_CREATE=0
SKIP_BOOTSTRAP=0
SKIP_STATUS=0

usage() {
  sed -n '2,12p' "$0"
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --operator) OPERATOR="$2"; shift 2 ;;
    --vps) VPS_HOST="$2"; shift 2 ;;
    --public-url) PUBLIC_URL="$2"; shift 2 ;;
    --port) HOST_PORT="$2"; shift 2 ;;
    --create) DO_CREATE=1; shift ;;
    --force-create) DO_CREATE=1; FORCE_CREATE=1; shift ;;
    --skip-bootstrap) SKIP_BOOTSTRAP=1; shift ;;
    --skip-status) SKIP_STATUS=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

[[ -n "$OPERATOR" ]] || { echo "missing --operator" >&2; usage 1; }
[[ -n "$VPS_HOST" ]] || { echo "missing --vps" >&2; usage 1; }

if ! command -v yakr >/dev/null 2>&1; then
  echo "yakr CLI not found — run: uv sync --all-packages && uv run yakr --help" >&2
  exit 1
fi

YAKR_HOME="${YAKR_HOME:-$HOME/.yakr}"
RELAY_HOME="$YAKR_HOME/relays/$OPERATOR"

if [[ ! -f "$RELAY_HOME/manifest.json" ]]; then
  if [[ "$DO_CREATE" != 1 ]]; then
    echo "Operator bundle missing at $RELAY_HOME" >&2
    echo "Re-run with --create --public-url https://HOST:8090" >&2
    exit 1
  fi
  [[ -n "$PUBLIC_URL" ]] || { echo "missing --public-url for --create" >&2; exit 1; }
  CREATE_ARGS=(relay create "$OPERATOR" --public-url "$PUBLIC_URL" --port "$HOST_PORT")
  if [[ "$FORCE_CREATE" == 1 ]]; then
    CREATE_ARGS+=(--force)
  fi
  echo "==> Creating relay operator bundle…"
  yakr "${CREATE_ARGS[@]}"
else
  echo "==> Using existing operator bundle: $RELAY_HOME"
fi

echo "==> Deploying to $VPS_HOST…"
yakr relay deploy "$OPERATOR" --vps "$VPS_HOST"

if [[ "$SKIP_BOOTSTRAP" != 1 ]]; then
  echo "==> Bootstrapping relay capabilities…"
  yakr relay capability-bootstrap "$OPERATOR" || {
    echo "WARN: capability bootstrap failed — relay may still be starting; retry:" >&2
    echo "  yakr relay capability-bootstrap $OPERATOR" >&2
  }
fi

if [[ "$SKIP_STATUS" != 1 ]]; then
  echo "==> Relay status…"
  yakr relay status "$OPERATOR" || true
fi

echo ""
echo "=== Homelab relay deploy complete ==="
echo ""
echo "Post-deploy (on your messaging device):"
echo "  yakr profile publish"
echo "  yakr profile push <contact>    # repeat for each paired peer"
echo "  yakr presence push             # if public URL or IP changed"
echo ""
echo "Peer verification:"
echo "  curl -k \$(jq -r .public_url $RELAY_HOME/manifest.json)/healthz"
echo ""
echo "Full runbook: docs/homelab-relay.md"
