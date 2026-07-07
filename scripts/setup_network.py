#!/usr/bin/env python3
"""Initialize demo identities and pairwise contacts for Docker testing."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

IDENTITIES = ("alice", "bob", "charlie", "dennis")
DATA_ROOT = Path("/data")


def run(home: Path, *args: str) -> None:
    subprocess.run(
        ["yakr", *args],
        check=True,
        env={
            **os.environ,
            "YAKR_HOME": str(home),
            "YAKR_RELAY_URL": "http://relay:8080",
        },
    )


def main() -> None:
    for name in IDENTITIES:
        home = DATA_ROOT / name
        home.mkdir(parents=True, exist_ok=True)
        run(home, "init", "--name", name, "--force")

    # Alice <-> Bob demo contact graph for Phase 1
    alice_home = DATA_ROOT / "alice"
    bob_home = DATA_ROOT / "bob"
    run(alice_home, "contact-add", "bob", str(bob_home / "public.json"))
    run(bob_home, "contact-add", "alice", str(alice_home / "public.json"))

    print("Yakr demo network ready: alice <-> bob")


if __name__ == "__main__":
    main()
