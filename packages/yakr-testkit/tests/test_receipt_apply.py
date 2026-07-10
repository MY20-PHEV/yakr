"""Tests for inbound delivery receipt handling."""

from __future__ import annotations

from pathlib import Path

from yakr_cli.network import deliver_encrypted
from yakr_core.receipt_apply import apply_inbound_delivery_receipt, has_outbound_pending
from yakr_core.session import Session
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_unknown_receipt_does_not_clear_pending(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "awaiting ack")
        assert mesh.alice.pending_count("bob") == 1

        bob_contact = mesh.bob.store.get_contact("alice")
        assert bob_contact is not None
        alice_contact = mesh.alice.store.get_contact("bob")
        assert alice_contact is not None
        before_seq = alice_contact.last_recv_seq
        bob_session = Session(mesh.bob.identity, bob_contact)
        unknown = bob_session.encrypt_receipt("cafebabe" * 8)
        deliver_encrypted(
            unknown,
            contact=bob_contact,
            identity=mesh.bob.identity,
            store=mesh.bob.store,
            allow_direct=False,
        )

        mesh.alice.drain_receipts()
        assert mesh.alice.pending_count("bob") == 1

        alice_contact = mesh.alice.store.get_contact("bob")
        assert alice_contact is not None
        assert alice_contact.last_recv_seq == before_seq + 1
    finally:
        mesh.stop()


def test_apply_inbound_delivery_receipt_unknown_returns_false(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "pending")
        bob_contact = mesh.bob.store.get_contact("alice")
        assert bob_contact is not None
        bob_session = Session(mesh.bob.identity, bob_contact)
        receipt_inner = bob_session.encrypt_receipt("deadbeef" * 8).inner_message

        assert not apply_inbound_delivery_receipt(mesh.alice.store, "bob", receipt_inner)
        assert has_outbound_pending(mesh.alice.store, "bob", mesh.alice.sent[-1].msg_id)
    finally:
        mesh.stop()
