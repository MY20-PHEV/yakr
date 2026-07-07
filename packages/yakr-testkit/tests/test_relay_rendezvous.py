from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.invite import create_invite, invite_from_url, invite_to_url
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted
from yakr_cli.profile_cmds import build_local_profile
from yakr_cli.relay_pairing import (
    inviter_wait_on_relay,
    poll_relay_pair_response,
    post_relay_pair_request,
)
from yakr_core.pairing import build_pairing_request, joiner_complete_pairing
from yakr_core.relay_authorization import assert_publish_relays_allowed, authorized_publish_relays
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore


def _start_charlie_relay(root: Path) -> tuple[str, uvicorn.Server, threading.Thread]:
    store = BlobStore(root / "charlie")
    pairing_store = PairingStore(root / "charlie")
    app = create_app(
        store,
        RelayRuntime(role="both", wrap_secret=secrets.token_bytes(32), name="charlie"),
        pairing_store=pairing_store,
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", server, thread


def _save_relay_operator_contact(
    store: FileLocalStore,
    local: Identity,
    operator: Identity,
    relay_url: str,
    wrap_secret: bytes,
) -> None:
    operator_profile = create_delivery_profile(
        operator,
        relay_descriptors=[
            RelayDescriptor(operator.name, "both", relay_url, wrap_secret),
        ],
    )
    contact = Contact.establish(local, operator.name, export_public_bundle(operator))
    contact.delivery_profile = operator_profile
    store.save_contact(contact)


def _joiner_accept(relay_url: str, invite_url: str, bob_store: FileLocalStore, bob: Identity) -> Contact:
    bundle = invite_from_url(invite_url)
    profile = build_local_profile(bob, store=bob_store)
    request, secrets_ = build_pairing_request(
        bob,
        bundle,
        joiner_name="bob",
        joiner_profile=profile.to_bytes(),
    )
    invite_tag = post_relay_pair_request(relay_url, request)
    pairing_response = poll_relay_pair_response(relay_url, invite_tag, timeout_secs=30.0)
    contact = joiner_complete_pairing(bob, bundle, request, secrets_, pairing_response)
    contact.name = "alice"
    bob_store.save_contact(contact)
    return contact


def test_bob_cannot_advertise_unpaired_relay(tmp_path: Path) -> None:
    relay_url, server, thread = _start_charlie_relay(tmp_path)
    wrap_secret = secrets.token_bytes(32)

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    charlie = Identity.generate("charlie")
    alice_store = FileLocalStore(tmp_path / "alice")
    bob_store = FileLocalStore(tmp_path / "bob")
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)

    _save_relay_operator_contact(alice_store, alice, charlie, relay_url, wrap_secret)

    alice_profile = build_local_profile(alice, store=alice_store)
    assert any(relay.url == relay_url for relay in alice_profile.relay_descriptors)

    bob_profile = build_local_profile(bob, store=bob_store)
    assert bob_profile.relay_descriptors == ()

    unauthorized = [
        RelayDescriptor("charlie", "both", relay_url, wrap_secret),
    ]
    authorized = authorized_publish_relays(identity_name=bob.name, contacts=[])
    with pytest.raises(ValueError, match="not paired with that relay operator"):
        assert_publish_relays_allowed(unauthorized, authorized)

    server.should_exit = True
    thread.join(timeout=2)


def test_charlie_relay_pairing_and_bidirectional_messages(tmp_path: Path) -> None:
    relay_url, server, thread = _start_charlie_relay(tmp_path)
    wrap_secret = secrets.token_bytes(32)

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    charlie = Identity.generate("charlie")
    alice_store = FileLocalStore(tmp_path / "alice")
    bob_store = FileLocalStore(tmp_path / "bob")
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)

    _save_relay_operator_contact(alice_store, alice, charlie, relay_url, wrap_secret)

    alice_profile = build_local_profile(alice, store=alice_store)
    alice_store.save_local_profile(alice_profile)
    bob_profile = build_local_profile(bob, store=bob_store)
    bob_store.save_local_profile(bob_profile)
    assert bob_profile.relay_descriptors == ()

    invite = create_invite(alice, rendezvous_hint=relay_url)
    invite_url = invite_to_url(invite)

    joiner_error: list[Exception] = []

    def run_joiner() -> None:
        try:
            time.sleep(0.2)
            _joiner_accept(relay_url, invite_url, bob_store, bob)
        except Exception as exc:
            joiner_error.append(exc)

    joiner_thread = threading.Thread(target=run_joiner)
    joiner_thread.start()

    inviter_profile = alice_store.load_local_profile()
    _, alice_contact = inviter_wait_on_relay(
        relay_url,
        alice,
        invite,
        inviter_profile=inviter_profile.to_bytes() if inviter_profile else b"",
        timeout_secs=30.0,
    )
    alice_contact.name = "bob"
    alice_store.save_contact(alice_contact)

    joiner_thread.join(timeout=10)
    assert not joiner_error, joiner_error[0] if joiner_error else None

    bob_contact = bob_store.get_contact("alice")
    assert bob_contact is not None
    assert bob_contact.delivery_profile is not None
    assert any(relay.url == relay_url for relay in bob_contact.delivery_profile.relay_descriptors)
    assert bob_store.load_local_profile() is not None
    assert bob_store.load_local_profile().relay_descriptors == ()

    encrypted = Session(alice, alice_contact).encrypt_text("hello from alice")
    deliver_encrypted(
        encrypted,
        contact=alice_contact,
        identity=alice,
        store=alice_store,
    )

    bob_session = Session(bob, bob_contact)
    fetched = httpx.get(
        f"{relay_url}/v1/blobs/{encrypted.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    assert fetched.status_code == 200
    assert len(fetched.json()) == 1
    from yakr_core.message import OuterBlob

    outer = OuterBlob.from_relay_json(fetched.json()[0])
    inner = bob_session.decrypt_outer(outer)
    assert inner.body == "hello from alice"

    reply = Session(bob, bob_contact).encrypt_text("hello from bob")
    deliver_encrypted(
        reply,
        contact=bob_contact,
        identity=bob,
        store=bob_store,
    )

    alice_session = Session(alice, alice_contact)
    reply_fetch = httpx.get(
        f"{relay_url}/v1/blobs/{reply.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    assert reply_fetch.status_code == 200
    reply_outer = OuterBlob.from_relay_json(reply_fetch.json()[0])
    reply_inner = alice_session.decrypt_outer(reply_outer)
    assert reply_inner.body == "hello from bob"

    server.should_exit = True
    thread.join(timeout=2)
