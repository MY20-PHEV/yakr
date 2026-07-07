from __future__ import annotations

import base64
import threading
import time

import httpx
import pytest
import uvicorn

from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.invite import create_invite, invite_from_url, invite_to_url, safety_code, verify_invite
from yakr_core.pairing import (
    PairingResponse,
    build_pairing_request,
    inviter_complete_pairing,
    joiner_complete_pairing,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from yakr_core.relay_ticket import issue_relay_ticket, verify_relay_ticket
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore
from yakr_cli.rendezvous import RendezvousState, create_rendezvous_app


@pytest.fixture
def ticketed_relay(tmp_path):
    store = BlobStore(tmp_path / "relay")
    runtime = RelayRuntime(role="mailbox", wrap_secret=None, name="relay", require_tickets=True)
    app = create_app(store, runtime)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    yield url
    server.should_exit = True
    thread.join(timeout=2)


def test_invite_pairing_via_rendezvous() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test")
    verify_invite(invite)
    url = invite_to_url(invite)
    parsed = invite_from_url(url)
    assert safety_code(parsed) == safety_code(invite)

    state = RendezvousState(invite=invite, identity=alice)
    app = create_rendezvous_app(state)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"

    request, bob_ephemeral = build_pairing_request(bob, invite, joiner_name="bob")
    encoded = base64.urlsafe_b64encode(request.to_bytes()).decode("ascii").rstrip("=")
    response = httpx.post(f"{base}/v1/pair", json={"request": encoded}, timeout=5.0)
    assert response.status_code == 200

    pairing_response = PairingResponse.from_bytes(
        base64.urlsafe_b64decode(response.json()["response"] + "==")
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, bob_ephemeral, pairing_response)
    assert bob_contact.ratchet is not None
    assert state.paired_contact is not None
    assert state.paired_contact.ratchet is not None

    replay = httpx.post(f"{base}/v1/pair", json={"request": encoded}, timeout=5.0)
    assert replay.status_code == 409

    server.should_exit = True
    thread.join(timeout=2)


def test_relay_requires_ticket(ticketed_relay: str) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    encrypted = Session(alice, contact).encrypt_text("ticketed")
    payload = encrypted.outer_blob.to_relay_json()

    denied = httpx.post(f"{ticketed_relay}/v1/blobs", json=payload, timeout=5.0)
    assert denied.status_code == 401

    ticket = issue_relay_ticket(
        alice,
        relay_name="relay",
        permissions=("store",),
        contact_id=b"\x01" * 32,
    )
    payload["ticket"] = ticket.to_b64()
    allowed = httpx.post(f"{ticketed_relay}/v1/blobs", json=payload, timeout=5.0)
    assert allowed.status_code == 201
    verify_relay_ticket(ticket, relay_name="relay", permission="store")


def test_ratchet_state_persists(tmp_path) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test")
    request, bob_ephemeral = build_pairing_request(bob, invite, joiner_name="bob")
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, bob_ephemeral, response)

    store = FileLocalStore(tmp_path / "bob")
    store.save_contact(bob_contact)
    reloaded = store.get_contact(bob_contact.name)
    assert reloaded is not None
    assert reloaded.ratchet is not None

    session = Session(bob, reloaded)
    encrypted = Session(alice, alice_contact).encrypt_text("persisted ratchet")
    inner = session.decrypt_outer(encrypted.outer_blob)
    assert inner.body == "persisted ratchet"
