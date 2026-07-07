#!/usr/bin/env python3
"""Alice + Bob locally, Charlie relay on localhost (VPS stand-in).

Alice is paired with Charlie (relay operator). Bob is not.
Pair Alice/Bob via Charlie rendezvous; messages flow via Charlie without
Bob advertising Charlie in his profile.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / ".tmp-relay-group-demo"
CHARLIE_PORT = 19080
CHARLIE_URL = f"http://127.0.0.1:{CHARLIE_PORT}"


def _run(cmd: list[str], *, env: dict[str, str]) -> str:
    result = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _start_charlie() -> tuple[uvicorn.Server, threading.Thread]:
    data_dir = DEMO / "charlie"
    store = BlobStore(data_dir)
    pairing_store = PairingStore(data_dir)
    app = create_app(
        store,
        RelayRuntime(role="both", wrap_secret=secrets.token_bytes(32), name="charlie"),
        pairing_store=pairing_store,
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=CHARLIE_PORT, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server, thread


def _save_charlie_contact_for_alice(charlie: Identity, wrap_secret: bytes) -> None:
    alice_home = DEMO / "alice"
    charlie_profile = create_delivery_profile(
        charlie,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", CHARLIE_URL, wrap_secret),
        ],
    )
    contact = Contact.establish(
        Identity.load(alice_home / "identity.json"),
        "charlie",
        export_public_bundle(charlie),
    )
    contact.delivery_profile = charlie_profile
    alice_home.mkdir(parents=True, exist_ok=True)
    (alice_home / "contacts").mkdir(exist_ok=True)
    (alice_home / "contacts" / "charlie.json").write_text(
        json.dumps(contact.to_dict(), indent=2),
        encoding="utf-8",
    )


def main() -> None:
    if DEMO.exists():
        shutil.rmtree(DEMO)
    DEMO.mkdir()

    print("Starting Charlie relay (VPS stand-in)…")
    server, thread = _start_charlie()
    assert httpx.get(f"{CHARLIE_URL}/healthz", timeout=5).status_code == 200

    charlie = Identity.generate("charlie")
    wrap_secret = secrets.token_bytes(32)

    def env_for(name: str) -> dict[str, str]:
        base = os.environ.copy()
        base["YAKR_HOME"] = str(DEMO / name)
        base["YAKR_NAME"] = name
        if name == "alice":
            base["YAKR_RELAY_URL"] = CHARLIE_URL
            base["YAKR_RELAY_NAME"] = "charlie"
        return base

    uv = ["uv", "run", "yakr"]

    print("Initializing Alice and Bob…")
    _run([*uv, "init", "--name", "alice"], env=env_for("alice"))
    _run([*uv, "init", "--name", "bob"], env=env_for("bob"))

    print("Alice paired with Charlie (relay operator)…")
    _save_charlie_contact_for_alice(charlie, wrap_secret)

    _run([*uv, "profile", "publish"], env=env_for("alice"))
    _run([*uv, "profile", "publish"], env=env_for("bob"))

    invite_url_path = DEMO / "alice" / "invites" / "latest.url"

    def bob_accept() -> None:
        for _ in range(50):
            if invite_url_path.exists():
                break
            time.sleep(0.1)
        invite_url = invite_url_path.read_text(encoding="utf-8").strip()
        _run([*uv, "invite", "accept", invite_url, "--name", "alice"], env=env_for("bob"))

    print("Alice creating invite on Charlie rendezvous…")
    _run(
        [*uv, "invite", "create", "--rendezvous", CHARLIE_URL, "--no-wait"],
        env=env_for("alice"),
    )

    bob_thread = threading.Thread(target=bob_accept)
    bob_thread.start()

    print("Alice waiting for Bob via Charlie…")
    _run(
        [*uv, "invite", "relay", "wait"],
        env=env_for("alice"),
    )

    bob_thread.join(timeout=30)

    print("Alice → Bob (via Alice's paired relay)")
    _run([*uv, "send", "bob", "hello from alice"], env=env_for("alice"))
    out = _run([*uv, "fetch", "alice"], env=env_for("bob"))
    assert "hello from alice" in out

    print("Bob → Alice (via Alice's advertised relay)")
    _run([*uv, "send", "alice", "hello from bob"], env=env_for("bob"))
    out = _run([*uv, "fetch", "bob"], env=env_for("alice"))
    assert "hello from bob" in out

    print("OK: relay pairing + bidirectional delivery via Charlie (Bob not paired with Charlie)")
    server.should_exit = True
    thread.join(timeout=2)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(exc.stdout)
        print(exc.stderr, file=sys.stderr)
        raise
