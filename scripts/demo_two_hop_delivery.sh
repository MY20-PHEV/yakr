#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ROUTE="dennis,charlie"
RECEIPT_ROUTE="charlie,dennis"

echo "==> Building images"
docker compose build relay dennis-relay charlie-relay setup alice bob

echo "==> Starting relays"
docker compose up -d relay dennis-relay charlie-relay

echo "==> Waiting for relay health"
until curl -sf http://127.0.0.1:8080/healthz >/dev/null \
  && curl -sf http://127.0.0.1:8081/healthz >/dev/null \
  && curl -sf http://127.0.0.1:8082/healthz >/dev/null; do
  sleep 1
done

echo "==> Bootstrapping identities and relay network"
docker compose run --rm setup

echo "==> Alice sends via two-hop route"
docker compose run --rm --no-deps alice send bob "hello two-hop" --route "$ROUTE"

echo "==> Bob fetches and returns delivery receipt"
docker compose run --rm --no-deps bob fetch alice --route "$ROUTE"

echo "==> Alice receives receipt"
docker compose run --rm --no-deps alice fetch bob --route "$RECEIPT_ROUTE"

echo "==> Alice pending queue should be empty"
docker compose run --rm --no-deps alice pending bob

echo "==> Two-hop demo complete"
