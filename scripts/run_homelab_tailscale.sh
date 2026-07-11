#!/usr/bin/env bash
# Run homelab mesh tests against Charlie + Dennis over Tailscale.
#
#   ./scripts/run_homelab_tailscale.sh              # mesh tests
#   ./scripts/run_homelab_tailscale.sh --cert       # certification self-test too
#   ./scripts/run_homelab_tailscale.sh --stress     # hybrid homelab stress (live)

set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck source=scripts/homelab_tailscale.env.sh
source scripts/homelab_tailscale.env.sh || {
  echo "Configure scripts/homelab_tailscale.local.env first (see .example)." >&2
  exit 1
}

echo "=== Homelab Tailscale ==="
echo "Charlie: $CHARLIE_URL"
echo "Dennis:  $DENNIS_URL"
echo "SSH:     $VPS_HOST"
echo "Legacy GET fetch: ${YAKR_LEGACY_GET_FETCH:-0}"
echo ""

if ! curl -sk --connect-timeout 3 "${CHARLIE_URL}/healthz" >/dev/null; then
  echo "ERROR: cannot reach Charlie at $CHARLIE_URL (is Tailscale up?)" >&2
  exit 1
fi
if ! curl -sk --connect-timeout 3 "${DENNIS_URL}/healthz" >/dev/null; then
  echo "ERROR: cannot reach Dennis at $DENNIS_URL" >&2
  exit 1
fi

if [[ ! -f "${CHARLIE_OPERATOR_HOME}/identity.json" ]]; then
  echo "ERROR: missing ${CHARLIE_OPERATOR_HOME}/identity.json" >&2
  echo "Generate operator homes or set CHARLIE_OPERATOR_HOME / DENNIS_OPERATOR_HOME" >&2
  exit 1
fi

echo "--- homelab mesh tests ---"
uv run pytest packages/yakr-testkit/tests/test_homelab_mesh.py -m homelab -q

if [[ "${1:-}" == "--cert" ]]; then
  echo ""
  echo "--- certification self-test ---"
  ./scripts/certification_self_test.sh
fi

if [[ "${1:-}" == "--stress" ]]; then
  echo ""
  echo "--- hybrid homelab stress (live) ---"
  uv run python scripts/hybrid_homelab_stress.py --live
fi

echo ""
echo "OK — homelab Tailscale path verified."
