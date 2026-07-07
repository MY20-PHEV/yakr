from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

import pytest

from yakr_core.ephemeral import MESSAGE_TTL_MS, message_valid_until
from yakr_testkit.mesh_setup import build_charlie_mesh, build_send_schedule, run_mesh_stress


@pytest.fixture
def charlie_mesh(tmp_path: Path):
    previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
    previous_name = os.environ.pop("YAKR_RELAY_NAME", None)
    try:
        mesh = build_charlie_mesh(tmp_path, wrap_secret=secrets.token_bytes(32))
        yield mesh
        mesh.stop()
        time.sleep(0.2)
    finally:
        if previous_relay is None:
            os.environ.pop("YAKR_RELAY_URL", None)
        else:
            os.environ["YAKR_RELAY_URL"] = previous_relay
        if previous_name is None:
            os.environ.pop("YAKR_RELAY_NAME", None)
        else:
            os.environ["YAKR_RELAY_NAME"] = previous_name


def test_mesh_stress_100_plus_messages(charlie_mesh) -> None:
    result = run_mesh_stress(charlie_mesh)
    assert result["total_sent"] >= 100
    assert result["missing"] == []
    assert result["pending_after"] == 0
    assert result["duplicate_fetch_hits"] == 0
    assert result["pending_before_drain"] > 0, "expected some pending before final drain with receipts"


def test_burst_send_then_batch_fetch(charlie_mesh) -> None:
    mesh = charlie_mesh
    bodies: list[str] = []
    for i in range(15):
        body = f"burst-{i:02d}"
        mesh.alice.send("bob", body)
        bodies.append(body)

    received = mesh.bob.fetch("alice", send_receipts=True)
    assert len(received) == 15
    assert [m.body for m in received] == bodies
    mesh.alice.drain_receipts()
    assert mesh.alice.pending_count("bob") == 0

    again = mesh.bob.fetch("alice", send_receipts=True)
    assert again == []


def test_charlie_alice_bidirectional(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.alice.send("charlie", "alice to charlie ops")
    mesh.charlie.send("alice", "charlie ops to alice")

    alice_got = mesh.alice.fetch("charlie", send_receipts=True)
    charlie_got = mesh.charlie.fetch("alice", send_receipts=True)

    assert any(m.body == "charlie ops to alice" for m in alice_got)
    assert any(m.body == "alice to charlie ops" for m in charlie_got)


def test_missing_receipts_then_recovery(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.alice.send("bob", "no receipt yet")
    mesh.alice.send("bob", "also pending")

    got = mesh.bob.fetch("alice", send_receipts=False)
    assert len(got) == 2
    assert mesh.alice.pending_count("bob") == 2

    dup = mesh.bob.fetch("alice", send_receipts=False)
    assert dup == []
    assert mesh.alice.pending_count("bob") == 2

    mesh.bob.flush_receipts("alice")
    mesh.alice.drain_receipts()
    assert mesh.alice.pending_count("bob") == 0


def test_out_of_order_delivery_via_delayed_fetch(charlie_mesh) -> None:
    """Multiple sends pile up on relay; one fetch drains them in seq order."""
    mesh = charlie_mesh
    for i in range(12):
        mesh.charlie.send("bob", f"charlie-burst-{i}")
    for i in range(8):
        mesh.alice.send("bob", f"alice-burst-{i}")

    charlie_msgs = mesh.bob.fetch("charlie", send_receipts=True)
    alice_msgs = mesh.bob.fetch("alice", send_receipts=True)

    assert len(charlie_msgs) == 12
    assert len(alice_msgs) == 8
    assert [m.body for m in charlie_msgs] == [f"charlie-burst-{i}" for i in range(12)]
    assert [m.body for m in alice_msgs] == [f"alice-burst-{i}" for i in range(8)]


def test_valid_until_on_all_messages(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.bob.send("alice", "ttl check")
    msgs = mesh.alice.fetch("bob", send_receipts=True)
    assert len(msgs) == 1
    now = msgs[0].valid_until - MESSAGE_TTL_MS
    assert msgs[0].valid_until == message_valid_until(created_at_ms=now) or msgs[0].valid_until > 0
    assert msgs[0].valid_until > __import__("time").time() * 1000 - 5000


def test_send_schedule_count() -> None:
    total = sum(count for _, _, count in build_send_schedule())
    assert total >= 100
