#!/usr/bin/env python3
"""Phase 6 hybrid PQ pairing demo."""

from __future__ import annotations

import base64
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from yakr_core.identity import Identity
from yakr_core.invite import create_invite, invite_supports_hybrid, verify_invite
from yakr_core.pairing import PairingResponse, build_pairing_request, joiner_complete_pairing
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.rendezvous import RendezvousState, create_rendezvous_app


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".tmp-hybrid-demo"
    if root.exists():
        import shutil

        shutil.rmtree(root)
    alice_home = root / "alice"
    bob_home = root / "bob"
    alice_home.mkdir(parents=True)
    bob_home.mkdir(parents=True)

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(alice_home)
    bob_store = FileLocalStore(bob_home)
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)

    invite = create_invite(alice, rendezvous_hint="http://127.0.0.1:18110", hybrid_pq=True)
    verify_invite(invite)
    assert invite_supports_hybrid(invite)

    state = RendezvousState(invite=invite, identity=alice)
    app = create_rendezvous_app(state)
    config = uvicorn.Config(app, host="127.0.0.1", port=18110, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)

    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    encoded = base64.urlsafe_b64encode(request.to_bytes()).decode("ascii").rstrip("=")
    response = httpx.post("http://127.0.0.1:18110/v1/pair", json={"request": encoded}, timeout=5.0)
    response.raise_for_status()
    pairing_response = PairingResponse.from_bytes(
        base64.urlsafe_b64decode(response.json()["response"] + "==")
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, pairing_response)
    bob_store.save_contact(bob_contact)
    assert state.paired_contact is not None
    alice_store.save_contact(state.paired_contact)

    encrypted = Session(alice, state.paired_contact).encrypt_text("hybrid pq hello")
    inner = Session(bob, bob_contact).decrypt_outer(encrypted.outer_blob)
    print(f"Hybrid paired; bob received: {inner.body}")
    print(f"hybrid_pq={bob_contact.hybrid_pq}, ratchet.hybrid={bob_contact.ratchet.hybrid}")

    server.should_exit = True
    print("Hybrid pairing demo complete")


if __name__ == "__main__":
    main()
