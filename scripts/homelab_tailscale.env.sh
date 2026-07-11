# Tailscale homelab — Charlie + Dennis (private config required)
#
# Copy scripts/homelab_tailscale.local.env.example → homelab_tailscale.local.env
# and set your Tailscale IP, SSH user, and wrap secrets. The local file is gitignored.
#
# Usage:
#   ./scripts/run_homelab_tailscale.sh

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_LOCAL_ENV="${_SCRIPT_DIR}/homelab_tailscale.local.env"

if [[ ! -f "$_LOCAL_ENV" ]]; then
  echo "Missing $_LOCAL_ENV" >&2
  echo "Copy scripts/homelab_tailscale.local.env.example and fill in your values." >&2
  return 1 2>/dev/null || exit 1
fi

# shellcheck source=/dev/null
source "$_LOCAL_ENV"

: "${HOMELAB_TAILSCALE_IP:?Set HOMELAB_TAILSCALE_IP in homelab_tailscale.local.env}"
: "${HOMELAB_SSH_USER:?Set HOMELAB_SSH_USER in homelab_tailscale.local.env}"
: "${CHARLIE_WRAP_SECRET:?Set CHARLIE_WRAP_SECRET in homelab_tailscale.local.env}"
: "${DENNIS_WRAP_SECRET:?Set DENNIS_WRAP_SECRET in homelab_tailscale.local.env}"

export VPS_HOST="${VPS_HOST:-${HOMELAB_SSH_USER}@${HOMELAB_TAILSCALE_IP}}"
export CHARLIE_VPS_HOST="${CHARLIE_VPS_HOST:-$VPS_HOST}"
export DENNIS_VPS_HOST="${DENNIS_VPS_HOST:-$VPS_HOST}"

export CHARLIE_URL="${CHARLIE_URL:-https://${HOMELAB_TAILSCALE_IP}:8090}"
export DENNIS_URL="${DENNIS_URL:-https://${HOMELAB_TAILSCALE_IP}:8091}"
export ALICE_OPS_PORT="${ALICE_OPS_PORT:-8092}"
export ALICE_OPS_URL="${ALICE_OPS_URL:-https://${HOMELAB_TAILSCALE_IP}:${ALICE_OPS_PORT}}"

_REPO_ROOT="$(cd "${_SCRIPT_DIR}/.." && pwd)"
export CHARLIE_OPERATOR_HOME="${CHARLIE_OPERATOR_HOME:-${_REPO_ROOT}/.tmp-homelab-operators/charlie-operator}"
export DENNIS_OPERATOR_HOME="${DENNIS_OPERATOR_HOME:-${_REPO_ROOT}/.tmp-homelab-operators/dennis-operator}"

export YAKR_REQUIRE_TLS=1
export YAKR_LEGACY_GET_FETCH="${YAKR_LEGACY_GET_FETCH:-1}"
