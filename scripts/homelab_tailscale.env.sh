# Tailscale homelab — Charlie + Dennis on `homelab` (REDACTED_TAILSCALE_IP)
#
# Usage:
#   source scripts/homelab_tailscale.env.sh
#   ./scripts/run_homelab_tailscale.sh
#
# SSH user: devos (see docs/spec/five-peer-homelab-relay-test.md)

export HOMELAB_TAILSCALE_IP="${HOMELAB_TAILSCALE_IP:-REDACTED_TAILSCALE_IP}"
export HOMELAB_SSH_USER="${HOMELAB_SSH_USER:-devos}"
export VPS_HOST="${VPS_HOST:-${HOMELAB_SSH_USER}@${HOMELAB_TAILSCALE_IP}}"
export CHARLIE_VPS_HOST="${CHARLIE_VPS_HOST:-$VPS_HOST}"
export DENNIS_VPS_HOST="${DENNIS_VPS_HOST:-$VPS_HOST}"

export CHARLIE_URL="${CHARLIE_URL:-https://${HOMELAB_TAILSCALE_IP}:8090}"
export DENNIS_URL="${DENNIS_URL:-https://${HOMELAB_TAILSCALE_IP}:8091}"
export ALICE_OPS_PORT="${ALICE_OPS_PORT:-8092}"
export ALICE_OPS_URL="${ALICE_OPS_URL:-https://${HOMELAB_TAILSCALE_IP}:${ALICE_OPS_PORT}}"

# Operator TLS + identity (repo-local; generate with scripts/generate_operator_relay_tls.py)
_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CHARLIE_OPERATOR_HOME="${CHARLIE_OPERATOR_HOME:-${_REPO_ROOT}/.tmp-homelab-operators/charlie-operator}"
export DENNIS_OPERATOR_HOME="${DENNIS_OPERATOR_HOME:-${_REPO_ROOT}/.tmp-homelab-operators/dennis-operator}"

# Wrap secrets must match the running containers (see five-peer-homelab-relay-test.md)
export CHARLIE_WRAP_SECRET="${CHARLIE_WRAP_SECRET:-ad3_Qrz0t6T-ftW-sUFk4d8jFnZNnpFkBMm2UXE3DmY}"
export DENNIS_WRAP_SECRET="${DENNIS_WRAP_SECRET:-FJXWbQSyAvPsI7wuGyG8_McBv9Qf-OKAFobDaobaTxQ}"

export YAKR_REQUIRE_TLS=1

# Homelab images deployed before POST /v1/fetch need legacy GET fetch until redeployed.
# After `scripts/deploy_charlie_vps.sh` + `deploy_dennis_vps.sh` with current repo, unset this.
export YAKR_LEGACY_GET_FETCH="${YAKR_LEGACY_GET_FETCH:-1}"
