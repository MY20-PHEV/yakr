#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uv sync --all-packages >/dev/null
uv run python scripts/demo_hybrid_pairing.py
