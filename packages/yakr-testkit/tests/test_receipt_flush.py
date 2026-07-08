"""CLI tests for queued delivery receipt flush."""

from __future__ import annotations

from pathlib import Path

from yakr_cli.receipt_cmds import flush_pending_receipts, send_delivery_receipt
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_cli_receipt_queue_survives_relay_outage(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.alice.send("bob", "cli receipt queue")
        record = mesh.alice.sent[-1]
        assert mesh.alice.pending_count("bob") == 1

        mesh.stop_all_relays()
        store = mesh.bob.store
        queued = send_delivery_receipt(
            store,
            mesh.bob.identity,
            "alice",
            record.msg_id,
        )
        assert queued is False
        assert store.list_pending_receipts("alice")

        assert flush_pending_receipts(store, mesh.bob.identity, contact_name="alice") == 0

        mesh.start_all_relays()
        sent = flush_pending_receipts(store, mesh.bob.identity, contact_name="alice")
        assert sent == 1
        assert not store.list_pending_receipts("alice")

        mesh.alice.drain_receipts()
        assert mesh.alice.pending_count("bob") == 0
    finally:
        mesh.stop()
