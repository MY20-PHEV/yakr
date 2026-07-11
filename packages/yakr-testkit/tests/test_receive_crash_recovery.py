"""P0-4 receive-path crash recovery via atomic receipt queue + fetch flush."""

from __future__ import annotations

from pathlib import Path

from yakr_cli.fetch_cmds import fetch_contact_inbound
from yakr_cli.receipt_cmds import send_delivery_receipt
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_receive_crash_before_receipt_send_recovered_on_next_fetch(
    tmp_path: Path,
    monkeypatch,
) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "survive receipt crash")
        assert mesh.alice.pending_count("bob") == 1

        attempts = {"count": 0}
        real_send = send_delivery_receipt

        def controlled_send(store, identity, contact_name, delivered_id, **kwargs):
            attempts["count"] += 1
            if attempts["count"] == 1:
                return False
            return real_send(store, identity, contact_name, delivered_id, **kwargs)

        monkeypatch.setattr("yakr_cli.fetch_cmds.send_delivery_receipt", controlled_send)
        monkeypatch.setattr("yakr_cli.receipt_cmds.send_delivery_receipt", controlled_send)

        first = fetch_contact_inbound(
            mesh.bob.store,
            mesh.bob.identity,
            "alice",
            quiet=True,
        )
        assert first == 1
        assert mesh.bob.store.list_pending_receipts("alice")
        assert mesh.alice.pending_count("bob") == 1

        second = fetch_contact_inbound(
            mesh.bob.store,
            mesh.bob.identity,
            "alice",
            quiet=True,
        )
        assert second == 0
        assert not mesh.bob.store.list_pending_receipts("alice")

        mesh.alice.drain_receipts()
        assert mesh.alice.pending_count("bob") == 0
    finally:
        mesh.stop()
