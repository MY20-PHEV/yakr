#!/usr/bin/env python3
"""Phase 4 invite pairing demo without pre-shared contact files."""

from __future__ import annotations

import base64
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from yakr_core.identity import Identity
from yakr_core.invite import create_invite, invite_to_url, safety_code, verify_invite
from yakr_core.pairing import PairingResponse, build_pairing_request, joiner_complete_pairing
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.rendezvous import RendezvousState, create_rendezvous_app


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".tmp-invite"
    if root.exists():
        import shutil

        shutil.rmtree(root)
    alice_home = root / "alice"
    bob_home = root / "bob"
    relay_dir = root / "relay"
    alice_home.mkdir(parents=True)
    bob_home.mkdir(parents=True)
    relay_dir.mkdir(parents=True)

    relay = subprocess.Popen(
        [
            "yakr-relay",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "18080",
            "--data-dir",
            str(relay_dir),
            "--require-tickets",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(alice_home)
    bob_store = FileLocalStore(bob_home)
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)

    invite = create_invite(alice, rendezvous_hint="http://127.0.0.1:18090")
    verify_invite(invite)
    code = safety_code(invite)

    state = RendezvousState(invite=invite, identity=alice)
    app = create_rendezvous_app(state)
    config = uvicorn.Config(app, host="127.0.0.1", port=18090, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)

    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    encoded = base64.urlsafe_b64encode(request.to_bytes()).decode("ascii").rstrip("=")
    response = httpx.post("http://127.0.0.1:18090/v1/pair", json={"request": encoded}, timeout=5.0)
    response.raise_for_status()
    pairing_response = PairingResponse.from_bytes(
        base64.urlsafe_b64decode(response.json()["response"] + "==")
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, pairing_response)
    bob_store.save_contact(bob_contact)
    assert state.paired_contact is not None
    alice_store.save_contact(state.paired_contact)

    assert safety_code(invite) == code
    print(f"Invite URL: {invite_to_url(invite)}")
    print(f"Safety code: {code}")
    print("Paired alice <-> bob via invite")

    import os

    env = {
        **os.environ,
        "YAKR_RELAY_URL": "http://127.0.0.1:18080",
        "YAKR_REQUIRE_TICKETS": "1",
        "YAKR_RELAY_NAME": "relay",
    }
    encrypted = Session(alice, state.paired_contact).encrypt_text("paired via invite")
    alice_store.save_contact(state.paired_contact)
    payload = encrypted.outer_blob.to_relay_json()
    from yakr_core.relay_ticket import issue_relay_ticket

    ticket = issue_relay_ticket(
        alice,
        relay_name="relay",
        permissions=("store",),
        contact_id=state.paired_contact.contact_id or b"",
    )
    payload["ticket"] = ticket.to_b64()
    store_response = httpx.post("http://127.0.0.1:18080/v1/blobs", json=payload, timeout=5.0)
    store_response.raise_for_status()

    reloaded = bob_store.get_contact("alice")
    assert reloaded is not None
    inner = Session(bob, reloaded).decrypt_outer(encrypted.outer_blob)
    bob_store.save_contact(reloaded)
    print(f"bob received: {inner.body}")

    relay.terminate()
    server.should_exit = True
    print("Invite pairing demo complete")


if __name__ == "__main__":
    main()
