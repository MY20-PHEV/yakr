#!/usr/bin/env python3
"""Initialize demo identities, contacts, and relay network for Docker testing."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
from pathlib import Path

from yakr_core.relay import RelayNode, save_relay_network

IDENTITIES = ("alice", "bob", "charlie", "dennis")
DATA_ROOT = Path("/data")
SHARED_ROOT = DATA_ROOT / "shared"

# Deterministic demo-only wrap secrets (never use in production).
DENNIS_WRAP = hashlib.sha256(b"yakr-demo-dennis-wrap-v0").digest()
CHARLIE_WRAP = hashlib.sha256(b"yakr-demo-charlie-wrap-v0").digest()


def _pair_all_identities() -> None:
    """Bidirectional contact-add for every pair (demo mesh, not invite flow)."""
    homes = {name: DATA_ROOT / name for name in IDENTITIES}
    for i, left in enumerate(IDENTITIES):
        for right in IDENTITIES[i + 1 :]:
            run(homes[left], "contact-add", right, str(homes[right] / "public.json"))
            run(homes[right], "contact-add", left, str(homes[left] / "public.json"))


def _relay_network() -> dict[str, RelayNode]:
    return {
        "dennis": RelayNode("dennis", "both", "http://dennis-relay:8081", DENNIS_WRAP),
        "charlie": RelayNode("charlie", "both", "http://charlie-relay:8082", CHARLIE_WRAP),
    }


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def run(home: Path, *args: str) -> None:
    subprocess.run(
        ["yakr", *args],
        check=True,
        env={
            **os.environ,
            "YAKR_HOME": str(home),
            "YAKR_RELAY_URL": "http://relay:8080",
            "YAKR_REQUIRE_TLS": "0",
        },
    )


def main() -> None:
    for name in IDENTITIES:
        home = DATA_ROOT / name
        home.mkdir(parents=True, exist_ok=True)
        db = home / "messages.db"
        if db.exists():
            db.unlink()
        run(home, "init", "--name", name, "--force")

    _pair_all_identities()

    SHARED_ROOT.mkdir(parents=True, exist_ok=True)
    save_relay_network(SHARED_ROOT / "relays.json", _relay_network())

    for name in IDENTITIES:
        run(DATA_ROOT / name, "profile", "publish")

    print("Yakr demo mesh ready: alice, bob, charlie, dennis (all paired)")
    print(f"Dennis wrap (dev): {_b64(DENNIS_WRAP)}")
    print(f"Charlie wrap (dev): {_b64(CHARLIE_WRAP)}")


if __name__ == "__main__":
    main()
