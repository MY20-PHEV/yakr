from __future__ import annotations

import json
import sqlite3

import pytest

from yakr_core.errors import DuplicateSeqError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import OuterBlob
from yakr_core.session import Session
from yakr_core.store import FileLocalStore


@pytest.fixture
def paired_stores(tmp_path):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(tmp_path / "alice")
    bob_store = FileLocalStore(tmp_path / "bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)
    alice_store.save_contact(alice_contact)
    bob_store.save_contact(bob_contact)
    return alice, bob, alice_contact, bob_contact, alice_store, bob_store


def test_atomic_send_persists_ratchet_and_pending_together(paired_stores) -> None:
    alice, _bob, alice_contact, _bob_contact, alice_store, _bob_store = paired_stores
    before_send_n = alice_contact.ratchet.send_n

    session = Session(alice, alice_contact)
    encrypted = session.encrypt_text("hello")
    alice_store.atomic_commit_send(
        alice_contact,
        msg_id=encrypted.msg_id,
        seq=encrypted.inner_message.seq,
        body="hello",
        outer=encrypted.outer_blob,
    )

    reloaded = alice_store.get_contact("bob")
    assert reloaded is not None
    assert reloaded.ratchet is not None
    assert reloaded.ratchet.send_n == before_send_n + 1
    assert reloaded.next_send_seq == 2
    pending = alice_store.list_outbound_pending("bob")
    assert pending == [(encrypted.msg_id, 1, "hello")]
    outer = alice_store.load_outbound_outer("bob", encrypted.msg_id)
    assert outer is not None
    assert outer.ciphertext == encrypted.outer_blob.ciphertext


def test_atomic_send_rolls_back_on_failure(paired_stores) -> None:
    alice, _bob, alice_contact, _bob_contact, alice_store, _bob_store = paired_stores
    reloaded = alice_store.get_contact("bob")
    assert reloaded is not None
    before = json.dumps(reloaded.to_dict())

    session = Session(alice, reloaded)
    encrypted = session.encrypt_text("rollback-test")
    alice_store.test_fault = "outbound_pending"

    with pytest.raises(sqlite3.OperationalError):
        alice_store.atomic_commit_send(
            reloaded,
            msg_id=encrypted.msg_id,
            seq=encrypted.inner_message.seq,
            body="rollback-test",
            outer=encrypted.outer_blob,
        )

    alice_store.test_fault = None
    persisted = alice_store.get_contact("bob")
    assert persisted is not None
    assert json.dumps(persisted.to_dict()) == before
    assert alice_store.list_outbound_pending("bob") == []
    assert alice_store.load_outbound_outer("bob", encrypted.msg_id) is None


def test_restart_after_atomic_send_does_not_reuse_ratchet_keys(paired_stores) -> None:
    alice, _bob, alice_contact, _bob_contact, alice_store, _bob_store = paired_stores

    session = Session(alice, alice_contact)
    first = session.encrypt_text("one")
    alice_store.atomic_commit_send(
        alice_contact,
        msg_id=first.msg_id,
        seq=first.inner_message.seq,
        body="one",
        outer=first.outer_blob,
    )

    reloaded = alice_store.get_contact("bob")
    assert reloaded is not None
    session2 = Session(alice, reloaded)
    second = session2.encrypt_text("two")
    assert first.outer_blob.ciphertext != second.outer_blob.ciphertext
    assert reloaded.ratchet is not None
    assert second.inner_message.seq == 2


def test_atomic_receive_persists_state_and_message(paired_stores) -> None:
    alice, bob, alice_contact, bob_contact, alice_store, bob_store = paired_stores

    encrypted = Session(alice, alice_contact).encrypt_text("delivered")
    bob_session = Session(bob, bob_contact)
    inner = bob_session.decrypt_outer(encrypted.outer_blob)

    bob_store.atomic_commit_receive_text(bob_contact, inner, identity=bob)

    reloaded = bob_store.get_contact("alice")
    assert reloaded is not None
    assert reloaded.last_recv_seq == 1
    rows = bob_store.list_inbound_messages("alice", bob)
    assert rows == [(1, "delivered")]

    with pytest.raises(DuplicateSeqError):
        Session(bob, reloaded).decrypt_outer(encrypted.outer_blob)


def test_atomic_receive_rolls_back_on_failure(paired_stores) -> None:
    alice, bob, alice_contact, bob_contact, _alice_store, bob_store = paired_stores
    encrypted = Session(alice, alice_contact).encrypt_text("recv-rollback")
    bob_reloaded = bob_store.get_contact("alice")
    assert bob_reloaded is not None
    before = json.dumps(bob_reloaded.to_dict())
    bob_session = Session(bob, bob_reloaded)
    inner = bob_session.decrypt_outer(encrypted.outer_blob)

    bob_store.test_fault = "inbound_message"

    with pytest.raises(sqlite3.OperationalError):
        bob_store.atomic_commit_receive_text(bob_reloaded, inner, identity=bob)

    bob_store.test_fault = None
    persisted = bob_store.get_contact("alice")
    assert persisted is not None
    assert json.dumps(persisted.to_dict()) == before
    assert bob_store.list_inbound_messages("alice", bob) == []


def test_contact_json_migrates_into_sqlite(tmp_path) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    store = FileLocalStore(tmp_path)
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    store.contacts_dir.mkdir(parents=True)
    store.contact_path("bob").write_text(json.dumps(contact.to_dict()), encoding="utf-8")

    loaded = store.get_contact("bob")
    assert loaded is not None
    assert loaded.master_secret == contact.master_secret

    with store._connect() as conn:  # noqa: SLF001
        row = conn.execute("SELECT 1 FROM contacts WHERE name = 'bob'").fetchone()
    assert row is not None
