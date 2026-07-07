from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


def run_yakr(
    identity_home: Path,
    *args: str,
    relay_url: str = "http://127.0.0.1:8080",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command = ["yakr", *args]
    merged = {
        "YAKR_HOME": str(identity_home),
        "YAKR_RELAY_URL": relay_url,
        **(env or {}),
    }
    return subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **merged},
    )


def bootstrap_pair(alice_home: Path, bob_home: Path) -> None:
    run_yakr(alice_home, "init", "--name", "alice", "--force")
    run_yakr(bob_home, "init", "--name", "bob", "--force")
    bob_public = bob_home / "public.json"
    alice_public = alice_home / "public.json"
    run_yakr(alice_home, "contact-add", "bob", str(bob_public))
    run_yakr(bob_home, "contact-add", "alice", str(alice_public))
