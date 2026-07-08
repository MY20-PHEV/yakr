#!/usr/bin/env bash
# Demo: Alice + Bob in local Docker, Charlie relay on your VPS.
#
# Prerequisites:
#   1. Deploy Charlie (HTTPS recommended):
#        python scripts/generate_operator_relay_tls.py ~/.yakr/charlie
#        CHARLIE_TLS_DIR=~/.yakr/charlie/relay-tls VPS_HOST=user@YOUR_VPS ./scripts/deploy_charlie_vps.sh
#   2. export CHARLIE_URL=https://YOUR_VPS_IP:8090
#   3. Open VPS firewall for TCP 8090 (or your CHARLIE_PORT)
#
# Dry-run against local charlie-relay instead of VPS:
#   docker compose up -d charlie-relay
#   export CHARLIE_URL=http://host.docker.internal:8082
#   export YAKR_REQUIRE_TLS=0
#   ./scripts/demo_vps_charlie_relay.sh

set -euo pipefail
cd "$(dirname "$0")/.."

CHARLIE_URL="${CHARLIE_URL:?set CHARLIE_URL to your VPS relay, e.g. https://203.0.113.10:8090}"
CHARLIE_URL="${CHARLIE_URL%/}"
HEALTH_URL="${CHARLIE_HEALTH_URL:-${CHARLIE_URL//host.docker.internal/127.0.0.1}}"

if [[ "$CHARLIE_URL" == https://* ]]; then
  export YAKR_REQUIRE_TLS="${YAKR_REQUIRE_TLS:-1}"
  CURL_TLS_OPTS=(-k)
else
  export YAKR_REQUIRE_TLS="${YAKR_REQUIRE_TLS:-0}"
  CURL_TLS_OPTS=()
fi

COMPOSE=(docker compose -f docker-compose.vps-charlie.yml)

echo "Checking Charlie relay at ${HEALTH_URL} (YAKR_REQUIRE_TLS=${YAKR_REQUIRE_TLS})…"
if ! curl -sf "${CURL_TLS_OPTS[@]}" "${HEALTH_URL}/healthz" >/dev/null; then
  echo "Cannot reach ${HEALTH_URL}/healthz"
  echo "Deploy with: CHARLIE_TLS_DIR=... VPS_HOST=user@YOUR_VPS ./scripts/deploy_charlie_vps.sh"
  echo "Local dry-run: docker compose up -d charlie-relay"
  echo "  export CHARLIE_URL=http://host.docker.internal:8082"
  echo "  export YAKR_REQUIRE_TLS=0"
  exit 1
fi

echo "Building Alice/Bob images…"
"${COMPOSE[@]}" build setup-vps-charlie alice bob

echo "Initializing identities (Alice paired with Charlie operator, Bob not)…"
"${COMPOSE[@]}" run --rm setup-vps-charlie

echo "Alice creates invite on Charlie rendezvous…"
"${COMPOSE[@]}" run --rm --no-deps alice \
  invite create --rendezvous "${CHARLIE_URL}" --no-wait

"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh alice \
  -c 'cp /data/invites/latest.url /data/shared/invite.url && cat /data/shared/invite.url'

echo "Alice registers on Charlie and waits for Bob…"
"${COMPOSE[@]}" run --rm --no-deps alice invite relay wait &
ALICE_PID=$!
sleep 2

echo "Bob accepts invite…"
"${COMPOSE[@]}" run --rm --no-deps --entrypoint sh bob \
  -c 'yakr invite accept "$(cat /data/shared/invite.url)" --name alice'

wait "$ALICE_PID"

echo ""
echo "Alice profile (should list charlie relay):"
"${COMPOSE[@]}" run --rm --no-deps alice profile show

echo ""
echo "Bob profile (should have no relay):"
"${COMPOSE[@]}" run --rm --no-deps bob profile show

echo ""
echo "Alice → Bob"
"${COMPOSE[@]}" run --rm --no-deps alice send bob "hello from alice via vps charlie"
"${COMPOSE[@]}" run --rm --no-deps bob fetch alice

echo ""
echo "Bob → Alice"
"${COMPOSE[@]}" run --rm --no-deps bob send alice "hello from bob via vps charlie"
"${COMPOSE[@]}" run --rm --no-deps alice fetch bob

echo ""
echo "OK: VPS Charlie rendezvous pairing + bidirectional messaging"
echo "    Alice advertises Charlie (paired). Bob does not."
