"""P0 fetch/receipt hardening tests for the Python reference client."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from yakr_cli.fetch_cmds import fetch_contact_inbound
from yakr_cli.network import deliver_encrypted
from yakr_cli.receipt_cmds import send_delivery_receipt
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_duplicate_fetch_is_idempotent(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "fetch once")
        first = mesh.bob.fetch("alice")
        second = mesh.bob.fetch("alice")
        assert len(first) == 1
        assert first[0].body == "fetch once"
        assert second == []
        rows = mesh.bob.store.list_inbound_messages("alice", mesh.bob.identity)
        assert len(rows) == 1
    finally:
        mesh.stop()


def test_stale_receipt_does_not_clear_unrelated_pending(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "still pending")
        assert mesh.alice.pending_count("bob") == 1

        bob_contact = mesh.bob.store.get_contact("alice")
        assert bob_contact is not None
        bob_session = Session(mesh.bob.identity, bob_contact)
        stale = bob_session.encrypt_receipt("deadbeef" * 8)
        deliver_encrypted(
            stale,
            contact=bob_contact,
            identity=mesh.bob.identity,
            store=mesh.bob.store,
            allow_direct=False,
        )

        mesh.alice.drain_receipts()
        assert mesh.alice.pending_count("bob") == 1
    finally:
        mesh.stop()


def test_receipt_failure_restores_ratchet(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "receipt ratchet")
        record = mesh.alice.sent[-1]
        bob_contact = mesh.bob.store.get_contact("alice")
        assert bob_contact is not None
        before_send_n = bob_contact.ratchet.send_n
        before_send_seq = bob_contact.next_send_seq

        mesh.stop_all_relays()
        ok = send_delivery_receipt(
            mesh.bob.store,
            mesh.bob.identity,
            "alice",
            record.msg_id,
        )
        assert ok is False

        restored = mesh.bob.store.get_contact("alice")
        assert restored is not None
        assert restored.ratchet is not None
        assert restored.ratchet.send_n == before_send_n
        assert restored.next_send_seq == before_send_seq
        assert mesh.bob.store.list_pending_receipts("alice")
    finally:
        mesh.stop()


def test_concurrent_fetch_uses_store_lock(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "threaded fetch")
        errors: list[BaseException] = []
        results: list[int] = []

        def worker() -> None:
            try:
                count = fetch_contact_inbound(
                    mesh.bob.store,
                    mesh.bob.identity,
                    "alice",
                    quiet=True,
                )
                results.append(count)
            except BaseException as exc:
                errors.append(exc)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start()
        t2.start()
        t1.join(timeout=30)
        t2.join(timeout=30)

        assert not errors
        assert sorted(results) == [0, 1]
        assert len(mesh.bob.store.list_inbound_messages("alice", mesh.bob.identity)) == 1
    finally:
        mesh.stop()


def test_fetch_lock_blocks_reentrant_fetch(tmp_path: Path) -> None:
    store = FileLocalStore(tmp_path)
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    store.save_identity(alice)
    store.save_contact(Contact.establish(alice, "bob", export_public_bundle(bob)))

    entered = threading.Event()
    release = threading.Event()

    def blocking_fetch() -> None:
        with store.fetch_lock():
            entered.set()
            release.wait(timeout=5)

    t = threading.Thread(target=blocking_fetch)
    t.start()
    assert entered.wait(timeout=5)

    acquired = threading.Event()

    def try_fetch() -> None:
        with store.fetch_lock():
            acquired.set()

    t2 = threading.Thread(target=try_fetch)
    t2.start()
    t2.join(timeout=0.2)
    assert not acquired.is_set()

    release.set()
    t.join(timeout=5)
    t2.join(timeout=5)
    assert acquired.is_set()
