#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Building images"
docker compose build

echo "==> Starting relay"
docker compose up -d relay

echo "==> Waiting for relay health"
until curl -sf http://127.0.0.1:8080/healthz >/dev/null; do
  sleep 1
done

echo "==> Bootstrapping identities"
docker compose run --rm setup

echo "==> Alice sends message while Bob is offline"
docker compose run --rm --no-deps alice send bob "hello from alice"

echo "==> Bob fetches message"
docker compose run --rm --no-deps bob fetch alice

echo "==> Demo complete"
