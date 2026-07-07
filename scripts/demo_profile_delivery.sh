#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
uv run python scripts/demo_profile_delivery.py
