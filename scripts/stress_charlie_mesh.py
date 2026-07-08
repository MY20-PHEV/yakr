#!/usr/bin/env python3
"""Stress-test Alice + Bob + Charlie messaging (100+ messages, burst patterns).

Local in-process relay (default):
  uv run python scripts/stress_charlie_mesh.py

Against homelab Charlie + Dennis (VPS trust model, no Bob↔Charlie shortcut):
  export CHARLIE_URL=https://YOUR_VPS:8090
  export DENNIS_URL=https://YOUR_VPS:8091
  export CHARLIE_OPERATOR_HOME=/path/to/charlie-operator   # must match deployed TLS certs
  export DENNIS_OPERATOR_HOME=/path/to/dennis-operator
  export CHARLIE_WRAP_SECRET=...
  export DENNIS_WRAP_SECRET=...
  uv run python scripts/stress_charlie_mesh.py --live

Failover test (optional):
  export CHARLIE_VPS_HOST=user@YOUR_VPS
  uv run pytest packages/yakr-testkit/tests/test_homelab_mesh.py -m homelab -v
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
        help="Use CHARLIE_URL + DENNIS_URL homelab relays (VPS trust model)",
    )
    args = parser.parse_args()

    if args.live:
        from yakr_testkit.homelab_mesh import build_homelab_mesh, homelab_env_configured

        if not homelab_env_configured():
            print("CHARLIE_URL and DENNIS_URL required for --live", file=sys.stderr)
            sys.exit(1)
        tmp = Path(tempfile.mkdtemp(prefix="yakr-homelab-stress-"))
        print(f"Homelab stress workspace: {tmp}")
        mesh = build_homelab_mesh(tmp)
    else:
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
