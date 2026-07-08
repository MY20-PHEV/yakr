#!/usr/bin/env python3
"""Initialize Alice + Bob for the VPS Charlie relay rendezvous demo.

Alice is paired with Charlie (relay operator contact). Bob is not.
Optional DENNIS_URL adds a second relay operator for send failover tests.

Requires CHARLIE_URL pointing at a reachable yakr-relay (pairing + blobs).
"""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile, relay_descriptor_for_operator
from yakr_core.identity import Contact, export_public_bundle

DATA_ROOT = Path("/data")
SHARED_ROOT = DATA_ROOT / "shared"
CHARLIE_OPERATOR_HOME = DATA_ROOT / "charlie-operator"
DENNIS_OPERATOR_HOME = DATA_ROOT / "dennis-operator"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _wrap_secret(env_name: str, *, fallback_seed: bytes) -> bytes:
    raw = os.environ.get(env_name)
    if raw:
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)
    return hashlib.sha256(fallback_seed).digest()


def run(home: Path, *args: str, extra_env: dict[str, str] | None = None) -> None:
    env = {**os.environ, "YAKR_HOME": str(home)}
    if extra_env:
        env.update(extra_env)
    env.pop("YAKR_RELAY_URL", None)
    env.pop("YAKR_RELAY_NAME", None)
    subprocess.run(["yakr", *args], check=True, env=env)


def main() -> None:
    charlie_url = os.environ.get("CHARLIE_URL", "").rstrip("/")
    dennis_url = os.environ.get("DENNIS_URL", "").rstrip("/")
    if not charlie_url:
        print("CHARLIE_URL is required (e.g. http://203.0.113.10:8080)", file=sys.stderr)
        sys.exit(1)

    charlie_wrap = _wrap_secret("CHARLIE_WRAP_SECRET", fallback_seed=b"yakr-demo-vps-charlie-wrap-v0")
    dennis_wrap = _wrap_secret("DENNIS_WRAP_SECRET", fallback_seed=b"yakr-demo-vps-dennis-wrap-v0")

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
            relay_descriptor_for_operator(charlie, "both", charlie_url, charlie_wrap),
        ],
    )
    charlie_contact = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    charlie_contact.delivery_profile = charlie_profile
    (DATA_ROOT / "alice" / "contacts").mkdir(parents=True, exist_ok=True)
    (DATA_ROOT / "alice" / "contacts" / "charlie.json").write_text(
        __import__("json").dumps(charlie_contact.to_dict(), indent=2),
        encoding="utf-8",
    )

    if dennis_url:
        DENNIS_OPERATOR_HOME.mkdir(parents=True, exist_ok=True)
        run(DENNIS_OPERATOR_HOME, "init", "--name", "dennis", "--force")
        dennis = Identity.load(DENNIS_OPERATOR_HOME / "identity.json")
        dennis_profile = create_delivery_profile(
            dennis,
            relay_descriptors=[
                relay_descriptor_for_operator(dennis, "both", dennis_url, dennis_wrap),
            ],
        )
        dennis_contact = Contact.establish(alice, "dennis", export_public_bundle(dennis))
        dennis_contact.delivery_profile = dennis_profile
        (DATA_ROOT / "alice" / "contacts" / "dennis.json").write_text(
            __import__("json").dumps(dennis_contact.to_dict(), indent=2),
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
    if dennis_url:
        (SHARED_ROOT / "dennis.url").write_text(dennis_url + "\n", encoding="utf-8")

    print("VPS Charlie demo identities ready")
    print(f"  Charlie relay: {charlie_url}")
    if dennis_url:
        print(f"  Dennis relay (failover): {dennis_url}")
        print("  Alice: paired with charlie + dennis; profile lists charlie then dennis")
    else:
        print("  Alice: paired with charlie operator, profile advertises charlie relay")
    print("  Bob: no relay operators in profile")
    print(f"  Charlie wrap (dev demo): {_b64(charlie_wrap)}")
    if dennis_url:
        print(f"  Dennis wrap (dev demo): {_b64(dennis_wrap)}")


if __name__ == "__main__":
    main()
