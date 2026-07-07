from __future__ import annotations

import time

import httpx
import pytest
from fastapi.testclient import TestClient

from yakr_core.ephemeral import MESSAGE_TTL_MS, message_valid_until
from yakr_core.errors import MessageExpiredError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.invite import create_invite
from yakr_core.message import InnerMessage, OuterBlob
from yakr_core.pairing import build_pairing_request, inviter_complete_pairing, joiner_complete_pairing
from yakr_core.privacy import pad_plaintext
from yakr_core.ratchet import RATCHET_MAGIC
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore
from cryptography.hazmat.primitives.asymmetric import x25519


@pytest.fixture
def relay_client(tmp_path):
    store = BlobStore(tmp_path / "relay")
    app = create_app(store, RelayRuntime(role="mailbox", wrap_secret=None, name="test"))
    with TestClient(app) as test_client:
        yield test_client


def _paired_contacts() -> tuple[Identity, Contact, Identity, Contact]:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test")
    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)
    return alice, alice_contact, bob, bob_contact


def test_double_ratchet_bidirectional() -> None:
    alice, alice_contact, bob, bob_contact = _paired_contacts()
    alice_session = Session(alice, alice_contact)
    bob_session = Session(bob, bob_contact)

    first = alice_session.encrypt_text("hello bob")
    assert first.outer_blob.ciphertext.startswith(RATCHET_MAGIC)
    inner = bob_session.decrypt_outer(first.outer_blob)
    assert inner.body == "hello bob"
    assert inner.valid_until == message_valid_until(created_at_ms=inner.created_at)

    reply = bob_session.encrypt_text("hello alice")
    back = alice_session.decrypt_outer(reply.outer_blob)
    assert back.body == "hello alice"


def test_double_ratchet_state_is_version_two(tmp_path) -> None:
    _, _, bob, bob_contact = _paired_contacts()
    store = FileLocalStore(tmp_path / "bob")
    store.save_contact(bob_contact)
    reloaded = store.get_contact(bob_contact.name)
    assert reloaded is not None
    assert reloaded.ratchet is not None
    assert reloaded.ratchet.to_dict()["version"] == 2


def test_message_ttl_enforced_on_decrypt() -> None:
    alice, alice_contact, bob, bob_contact = _paired_contacts()
    bob_session = Session(bob, bob_contact)

    old = int(time.time() * 1000) - MESSAGE_TTL_MS - 5_000
    inner = InnerMessage(
        version=1,
        conversation_id=alice_contact.conversation_id,
        sender_device_id=alice.device_id,
        seq=alice_contact.next_send_seq,
        created_at=old,
        valid_until=old + MESSAGE_TTL_MS,
        type="text",
        body="expires soon",
    )
    padded, _ = pad_plaintext(inner.to_bytes(), alice_contact.privacy_mode)
    ratchet_payload = alice_contact.ratchet.encrypt(padded)
    outer = OuterBlob(
        version=1,
        mailbox_tag=b"\x00" * 32,
        expires_at=int(time.time() * 1000) + 60_000,
        ciphertext=ratchet_payload,
    )
    with pytest.raises(MessageExpiredError):
        bob_session.decrypt_outer(outer)


def test_relay_rejects_blob_ttl_over_24h(relay_client) -> None:
    test_client = relay_client
    tag = b"\x21" * 32
    import base64

    now = int(time.time() * 1000)
    payload = {
        "mailbox_tag": base64.urlsafe_b64encode(tag).decode("ascii").rstrip("="),
        "expires_at": now + MESSAGE_TTL_MS + 60_000,
        "ciphertext": base64.urlsafe_b64encode(b"blob").decode("ascii").rstrip("="),
    }
    response = test_client.post("/v1/blobs", json=payload)
    assert response.status_code == 400
    assert "24 hour" in response.json()["detail"]


def test_ephemeral_local_store_encrypts_at_rest(tmp_path) -> None:
    alice, alice_contact, bob, bob_contact = _paired_contacts()
    bob_session = Session(bob, bob_contact)
    encrypted = Session(alice, alice_contact).encrypt_text("stored encrypted")
    inner = bob_session.decrypt_outer(encrypted.outer_blob)

    store = FileLocalStore(tmp_path / "bob")
    store.save_inbound_message("alice", inner, identity=bob)

    with store._connect() as conn:
        row = conn.execute(
            "SELECT local_ciphertext FROM inbound_messages WHERE contact_name = ?",
            ("alice",),
        ).fetchone()
    assert row is not None
    assert not bytes(row[0]).startswith(b'{"body"')

    listed = store.list_inbound_messages("alice", bob)
    assert listed == [(inner.seq, "stored encrypted")]


def test_local_sweeper_removes_expired_messages(tmp_path) -> None:
    alice, alice_contact, bob, bob_contact = _paired_contacts()
    bob_session = Session(bob, bob_contact)
    encrypted = Session(alice, alice_contact).encrypt_text("gone")
    inner = bob_session.decrypt_outer(encrypted.outer_blob)
    inner = InnerMessage(
        version=inner.version,
        conversation_id=inner.conversation_id,
        sender_device_id=inner.sender_device_id,
        seq=inner.seq,
        created_at=int(time.time() * 1000) - MESSAGE_TTL_MS - 1,
        valid_until=int(time.time() * 1000) - 1,
        type="text",
        body=inner.body,
    )

    store = FileLocalStore(tmp_path / "bob")
    store.save_inbound_message("alice", inner, identity=bob)
    assert store.sweep_expired_messages() == 1
    assert store.list_inbound_messages("alice", bob) == []


def test_offline_delivery_with_double_ratchet_and_24h_ttl(relay_server: str) -> None:
    alice, alice_contact, bob, bob_contact = _paired_contacts()
    encrypted = Session(alice, alice_contact).encrypt_text("ephemeral hello")
    assert encrypted.outer_blob.expires_at <= int(time.time() * 1000) + MESSAGE_TTL_MS + 1000

    response = httpx.post(
        f"{relay_server}/v1/blobs",
        json=encrypted.outer_blob.to_relay_json(),
        timeout=5.0,
    )
    assert response.status_code == 201

    bob_session = Session(bob, bob_contact)
    fetched = False
    for tag in bob_session.mailbox_deriver(outbound=False).candidate_epochs(bob_session.recv_direction):
        fetch = httpx.get(f"{relay_server}/v1/blobs/{tag.tag_b64}", timeout=5.0)
        for item in fetch.json():
            inner = bob_session.decrypt_outer(OuterBlob.from_relay_json(item))
            assert inner.body == "ephemeral hello"
            fetched = True
    assert fetched


def test_contact_establish_includes_double_ratchet() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    assert alice_contact.ratchet is not None
    assert bob_contact.ratchet is not None
    assert alice_contact.ratchet.to_dict()["version"] == 2

    encrypted = Session(alice, alice_contact).encrypt_text("via establish")
    inner = Session(bob, bob_contact).decrypt_outer(encrypted.outer_blob)
    assert inner.body == "via establish"
