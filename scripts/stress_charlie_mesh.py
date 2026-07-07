#!/usr/bin/env python3
"""Stress-test Alice + Bob + Charlie messaging (100+ messages, burst patterns).

Local in-process relay (default):
  uv run python scripts/stress_charlie_mesh.py

Against homelab Charlie (fresh docker identities):
  docker compose -f docker-compose.vps-charlie.yml down -v
  export CHARLIE_URL=http://100.125.109.114:8090
  docker compose -f docker-compose.vps-charlie.yml run --rm setup-vps-charlie
  uv run python scripts/stress_charlie_mesh.py --live

Live mode uses subprocess yakr in docker for setup then runs Python mesh in-process
with stores under /tmp or reuses docker volumes via compose exec — simpler to use
local mesh against CHARLIE_URL with freshly built mesh in temp dir.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT / "packages" / "yakr-testkit" / "src"))

from yakr_testkit.mesh_setup import build_charlie_mesh, run_mesh_stress  # noqa: E402


def _wrap_secret() -> bytes:
    raw = os.environ.get("CHARLIE_WRAP_SECRET")
    if raw:
        import base64

        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)
    return hashlib.sha256(b"yakr-demo-vps-charlie-wrap-v0").digest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Charlie mesh stress test")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use CHARLIE_URL from environment (homelab); does not start local relay",
    )
    args = parser.parse_args()

    if args.live:
        charlie_url = os.environ.get("CHARLIE_URL", "").rstrip("/")
        if not charlie_url:
            print("CHARLIE_URL required for --live", file=sys.stderr)
            sys.exit(1)
        print(f"Live mode not fully wired — use pytest against local relay or extend setup.")
        print(f"Recommended: uv run pytest packages/yakr-testkit/tests/test_mesh_stress.py -v")
        sys.exit(0)

    tmp = Path(tempfile.mkdtemp(prefix="yakr-mesh-stress-"))
    print(f"Mesh stress workspace: {tmp}")
    mesh = build_charlie_mesh(tmp, wrap_secret=secrets.token_bytes(32))
    try:
        result = run_mesh_stress(mesh)
        print(f"Sent: {result['total_sent']} messages")
        print(f"Missing: {len(result['missing'])}")
        print(f"Pending before final drain: {result['pending_before_drain']}")
        print(f"Pending after: {result['pending_after']}")
        print(f"Duplicate fetch hits (should be 0): {result['duplicate_fetch_hits']}")
        if result["missing"]:
            print("MISSING:", result["missing"][:10], "...")
            sys.exit(1)
        if result["pending_after"] != 0:
            print("FAIL: outbound still pending")
            sys.exit(1)
        print("OK: mesh stress passed")
    finally:
        mesh.stop()


if __name__ == "__main__":
    main()
