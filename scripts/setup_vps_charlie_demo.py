#!/usr/bin/env python3
"""Initialize Alice + Bob for the VPS Charlie relay rendezvous demo.

Alice is paired with Charlie (relay operator contact). Bob is not.
Requires CHARLIE_URL pointing at a reachable yakr-relay (pairing + blobs).
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, export_public_bundle

DATA_ROOT = Path("/data")
SHARED_ROOT = DATA_ROOT / "shared"
CHARLIE_OPERATOR_HOME = DATA_ROOT / "charlie-operator"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _wrap_secret() -> bytes:
    raw = os.environ.get("CHARLIE_WRAP_SECRET")
    if raw:
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)
    return hashlib.sha256(b"yakr-demo-vps-charlie-wrap-v0").digest()


def run(home: Path, *args: str, extra_env: dict[str, str] | None = None) -> None:
    env = {**os.environ, "YAKR_HOME": str(home)}
    if extra_env:
        env.update(extra_env)
    env.pop("YAKR_RELAY_URL", None)
    env.pop("YAKR_RELAY_NAME", None)
    subprocess.run(["yakr", *args], check=True, env=env)


def main() -> None:
    charlie_url = os.environ.get("CHARLIE_URL", "").rstrip("/")
    if not charlie_url:
        print("CHARLIE_URL is required (e.g. http://203.0.113.10:8080)", file=sys.stderr)
        sys.exit(1)

    wrap_secret = _wrap_secret()

    for name in ("alice", "bob"):
        home = DATA_ROOT / name
        home.mkdir(parents=True, exist_ok=True)
        db = home / "messages.db"
        if db.exists():
            db.unlink()
        run(home, "init", "--name", name, "--force")

    CHARLIE_OPERATOR_HOME.mkdir(parents=True, exist_ok=True)
    run(CHARLIE_OPERATOR_HOME, "init", "--name", "charlie", "--force")

    from yakr_core.identity import Identity

    alice = Identity.load(DATA_ROOT / "alice" / "identity.json")
    charlie = Identity.load(CHARLIE_OPERATOR_HOME / "identity.json")
    charlie_profile = create_delivery_profile(
        charlie,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", charlie_url, wrap_secret),
        ],
    )
    charlie_contact = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    charlie_contact.delivery_profile = charlie_profile
    (DATA_ROOT / "alice" / "contacts").mkdir(parents=True, exist_ok=True)
    (DATA_ROOT / "alice" / "contacts" / "charlie.json").write_text(
        __import__("json").dumps(charlie_contact.to_dict(), indent=2),
        encoding="utf-8",
    )

    run(DATA_ROOT / "alice", "profile", "publish")
    run(DATA_ROOT / "bob", "profile", "publish")

    SHARED_ROOT.mkdir(parents=True, exist_ok=True)
    public_path = SHARED_ROOT / "charlie-operator.public.json"
    public_path.write_text(
        (CHARLIE_OPERATOR_HOME / "public.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (SHARED_ROOT / "charlie.url").write_text(charlie_url + "\n", encoding="utf-8")

    print("VPS Charlie demo identities ready")
    print(f"  Charlie relay: {charlie_url}")
    print(f"  Alice: paired with charlie operator, profile advertises charlie relay")
    print(f"  Bob: no charlie relay in profile")
    print(f"  Charlie wrap (dev demo): {_b64(wrap_secret)}")


if __name__ == "__main__":
    main()
