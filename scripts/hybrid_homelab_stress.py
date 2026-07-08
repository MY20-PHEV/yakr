#!/usr/bin/env python3
"""Hybrid homelab stress: Alice (local) ↔ Bob via Charlie entry + Dennis mailbox.

Simulated (local in-process relays, split entry/mailbox roles):
  uv run python scripts/hybrid_homelab_stress.py

Live homelab (Dennis on VPS; Charlie local in-process or CHARLIE_URL):
  export DENNIS_URL=https://YOUR_HOMELAB:8091
  export DENNIS_OPERATOR_HOME=~/.yakr/dennis
  export DENNIS_WRAP_SECRET=...
  # optional local docker Charlie instead of in-process:
  # export CHARLIE_URL=https://127.0.0.1:8090
  # export CHARLIE_OPERATOR_HOME=~/.yakr/charlie
  uv run python scripts/hybrid_homelab_stress.py --live

Options:
  --messages 100       Total Alice↔Bob messages (default 100)
  --seed 42            RNG seed for reproducibility
  --fetch-min 1        Min seconds between fetch-all polls
  --fetch-max 3        Max seconds between fetch-all polls
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "packages" / "yakr-testkit" / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "packages" / "yakr-testkit" / "src"))

from yakr_testkit.hybrid_homelab_mesh import (  # noqa: E402
    assert_hybrid_trust_model,
    build_hybrid_homelab_mesh,
    hybrid_live_configured,
)
from yakr_testkit.hybrid_stress import (  # noqa: E402
    assert_hybrid_stress_passed,
    run_hybrid_alice_bob_stress,
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid homelab Alice↔Bob stress test")
    parser.add_argument("--live", action="store_true", help="Require DENNIS_URL homelab relay")
    parser.add_argument("--messages", type=int, default=100)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--fetch-min", type=float, default=1.0)
    parser.add_argument("--fetch-max", type=float, default=3.0)
    args = parser.parse_args()

    if args.live and not hybrid_live_configured():
        print("DENNIS_URL is required for --live", file=sys.stderr)
        sys.exit(1)

    tmp = Path(tempfile.mkdtemp(prefix="yakr-hybrid-stress-"))
    mode = "live" if args.live or hybrid_live_configured() else "simulated"
    print(f"Mode: {mode}")
    print(f"Workspace: {tmp}")
    if os.environ.get("DENNIS_URL"):
        print(f"Dennis relay: {os.environ['DENNIS_URL']}")
    if os.environ.get("CHARLIE_URL"):
        print(f"Charlie relay: {os.environ['CHARLIE_URL']}")
    else:
        print("Charlie relay: local in-process (entry)")

    mesh = build_hybrid_homelab_mesh(tmp, live=args.live or hybrid_live_configured())
    try:
        assert_hybrid_trust_model(mesh)
        result = run_hybrid_alice_bob_stress(
            mesh,
            total_messages=args.messages,
            fetch_interval_secs=(args.fetch_min, args.fetch_max),
            seed=args.seed,
        )
        print(f"Sent: {result.total_sent}")
        print(f"Missing inbound: {len(result.missing_inbound)}")
        print(f"Pending: alice={result.alice_pending} bob={result.bob_pending}")
        if result.fetch_errors:
            print(f"Fetch errors: {len(result.fetch_errors)}")
        assert_hybrid_stress_passed(result)
        print("OK: hybrid stress passed — histories match, all receipts cleared")
    finally:
        mesh.stop()


if __name__ == "__main__":
    main()
