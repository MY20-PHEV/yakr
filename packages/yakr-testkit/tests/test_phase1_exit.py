from __future__ import annotations

import time

import httpx
import pytest

from yakr_core.errors import DuplicateSeqError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_relay.store import BlobStore


def test_expired_blob_rejected_on_store(relay_server: str) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    session = Session(alice, contact)
    encrypted = session.encrypt_text("late")

    payload = encrypted.outer_blob.to_relay_json()
    payload["expires_at"] = int(time.time() * 1000) - 1000

    response = httpx.post(f"{relay_server}/v1/blobs", json=payload, timeout=5.0)
    assert response.status_code == 400


def test_sweeper_deletes_expired_blobs(tmp_path) -> None:
    store = BlobStore(tmp_path / "relay")
    tag = b"\x01" * 32
    past = int(time.time() * 1000) - 1000

    with store._connect() as conn:  # noqa: SLF001
        conn.execute(
            "INSERT INTO blobs (mailbox_tag, expires_at, ciphertext, stored_at) VALUES (?, ?, ?, ?)",
            (tag, past, b"cipher", past),
        )
        conn.commit()

    removed = store.sweep_expired()
    assert removed == 1
    assert store.fetch(tag) == []


def test_duplicate_seq_rejected() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))

    alice_session = Session(alice, alice_contact)
    encrypted = alice_session.encrypt_text("once")

    bob_session = Session(bob, bob_contact)
    bob_session.decrypt_outer(encrypted.outer_blob)
    with pytest.raises(DuplicateSeqError):
        bob_session.decrypt_outer(encrypted.outer_blob)


def test_relay_payload_has_no_plaintext(relay_server: str) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    session = Session(alice, contact)
    secret = "super-secret phrase"
    encrypted = session.encrypt_text(secret)

    payload = encrypted.outer_blob.to_relay_json()
    serialized = str(payload)
    assert secret not in serialized
    assert alice.name not in serialized
    assert bob.name not in serialized

    response = httpx.post(f"{relay_server}/v1/blobs", json=payload, timeout=5.0)
    assert response.status_code == 201
