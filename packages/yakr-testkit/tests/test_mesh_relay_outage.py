from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest

from yakr_testkit.mesh_setup import build_charlie_mesh, build_send_schedule


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


def test_relay_restart_preserves_queued_blobs(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.alice.send("bob", "survives restart")

    mesh.stop_relay()
    with pytest.raises((httpx.ConnectError, httpx.ReadError, OSError, httpx.HTTPError)):
        httpx.get(f"{mesh.relay_url}/v1/blobs/dummy", timeout=1.0, verify=False)

    mesh.start_all_relays()
    got = mesh.bob.fetch("alice", send_receipts=True)
    assert [m.body for m in got] == ["survives restart"]


def test_fetch_fails_while_relay_down_then_recovers(charlie_mesh) -> None:
    mesh = charlie_mesh
    for i in range(5):
        mesh.alice.send("bob", f"pre-outage-{i}")

    mesh.stop_relay()
    msgs, err = mesh.bob.try_fetch("alice", send_receipts=True)
    assert err is None
    assert msgs == []

    mesh.start_all_relays()
    got = mesh.bob.fetch("alice", send_receipts=True)
    assert len(got) == 5
    assert [m.body for m in got] == [f"pre-outage-{i}" for i in range(5)]


def test_send_fails_while_all_relays_down_pending_orphaned(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.stop_all_relays()

    record, err = mesh.alice.try_send("bob", "lost on outage")
    assert record is None
    assert err is not None
    assert mesh.alice.pending_count("bob") == 1

    mesh.start_all_relays()
    resent = mesh.alice.resend_pending("bob")
    assert len(resent) == 1

    got = mesh.bob.fetch("alice", send_receipts=True)
    assert [m.body for m in got] == ["lost on outage"]


def test_send_failover_to_dennis_when_charlie_down(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.stop_relay()

    record, err = mesh.alice.try_send("bob", "via dennis failover")
    assert err is None
    assert record is not None

    got = mesh.bob.fetch("alice", send_receipts=True)
    assert [m.body for m in got] == ["via dennis failover"]


def test_outage_mid_burst_failover_to_dennis(charlie_mesh) -> None:
    mesh = charlie_mesh
    for i in range(5):
        mesh.alice.send("bob", f"burst-{i}")

    mesh.stop_relay()
    for i in range(5, 10):
        mesh.alice.send("bob", f"burst-{i}")

    mesh.start_all_relays()
    got = mesh.bob.fetch("alice", send_receipts=True)
    assert len(got) == 10
    assert sorted(m.body for m in got) == [f"burst-{i}" for i in range(10)]


def test_outage_mid_burst_total_failure_when_all_relays_down(charlie_mesh) -> None:
    mesh = charlie_mesh
    delivered: list[str] = []
    failed: list[str] = []

    for i in range(10):
        body = f"burst-{i}"
        record, err = mesh.alice.try_send("bob", body)
        if err is None:
            delivered.append(body)
        else:
            failed.append(body)
        if i == 4:
            mesh.stop_all_relays()

    assert len(delivered) == 5
    assert len(failed) == 5

    mesh.start_all_relays()
    first_batch = mesh.bob.fetch("alice", send_receipts=True)
    assert len(first_batch) == 5
    mesh.alice.drain_receipts()
    assert mesh.alice.pending_count("bob") == 5

    resent = mesh.alice.resend_pending("bob")
    assert len(resent) == 5
    second_batch = mesh.bob.fetch("alice", send_receipts=True)
    assert len(second_batch) == 5
    assert sorted(m.body for m in first_batch + second_batch) == [f"burst-{i}" for i in range(10)]


def test_rapid_relay_flap_during_sends(charlie_mesh) -> None:
    mesh = charlie_mesh
    bodies: list[str] = []
    errors = 0

    for i in range(20):
        body = f"flap-{i:02d}"
        if i in {5, 10, 15}:
            mesh.stop_all_relays()
        if i in {7, 12, 17}:
            mesh.start_all_relays()
        record, err = mesh.alice.try_send("bob", body)
        if err is None:
            bodies.append(body)
        else:
            errors += 1

    mesh.start_all_relays()
    got = mesh.bob.fetch("alice", send_receipts=True)
    mesh.alice.drain_receipts()
    resent = mesh.alice.resend_pending("bob")
    if resent:
        got.extend(mesh.bob.fetch("alice", send_receipts=True))

    got_bodies = [m.body for m in got]
    for body in bodies:
        assert body in got_bodies, f"{body} missing after flap (sent ok but not fetched)"
    assert errors > 0, "expected some sends to fail during flap"


def test_concurrent_sends_during_relay_flap(charlie_mesh) -> None:
    mesh = charlie_mesh
    lock = threading.Lock()
    bodies: list[str] = []
    send_errors = 0

    mesh.stop_all_relays()

    def sender(prefix: str, count: int) -> None:
        nonlocal send_errors
        for i in range(count):
            body = f"{prefix}-{i}"
            record, err = mesh.alice.try_send("bob", body)
            with lock:
                bodies.append(body)
                if err is not None:
                    send_errors += 1

    threads = [
        threading.Thread(target=sender, args=("alice-a", 8)),
        threading.Thread(target=sender, args=("alice-b", 8)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads), "sender threads still running"
    assert send_errors == len(bodies), "expected all concurrent sends to fail while relay is down"

    mesh.start_all_relays()
    mesh.alice.resend_pending("bob")
    got = mesh.bob.fetch("alice", send_receipts=True)
    got_set = {m.body for m in got}
    for body in bodies:
        assert body in got_set, f"concurrent send {body} not delivered after resend"


def test_charlie_relay_outage_delays_fetch_until_primary_returns(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.alice.send("bob", "before")
    mesh.charlie.send("alice", "charlie-before")

    mesh.stop_relay()

    for party, peer in (
        (mesh.bob, "alice"),
        (mesh.alice, "charlie"),
    ):
        msgs, err = party.try_fetch(peer, send_receipts=True)
        assert err is None
        assert msgs == []

    mesh.start_all_relays()

    assert len(mesh.bob.fetch("alice", send_receipts=True)) == 1
    assert len(mesh.alice.fetch("charlie", send_receipts=True)) == 1


def test_stress_then_relay_kill_and_resume(charlie_mesh) -> None:
    """Run full send schedule, kill relay before fetch, resume and drain."""
    mesh = charlie_mesh
    participants = {
        "alice": mesh.alice,
        "bob": mesh.bob,
        "charlie": mesh.charlie,
    }
    expected: list[tuple[str, str, str]] = []

    for sender, recipient, count in build_send_schedule():
        party = participants[sender]
        for i in range(count):
            body = f"kill-{sender}-{recipient}-{i}"
            party.send(recipient, body)
            expected.append((sender, recipient, body))

    mesh.stop_relay()
    mesh.start_all_relays()

    for party in participants.values():
        party.flush_receipts()
        for peer in party.store.list_contacts():
            party.fetch(peer, send_receipts=True)

    received_by: dict[tuple[str, str], list[str]] = {}
    for recipient_name, party in participants.items():
        for sender_name in party.store.list_contacts():
            bodies = [
                body
                for _seq, body in party.store.list_inbound_messages(sender_name, party.identity)
            ]
            received_by[(sender_name, recipient_name)] = bodies

    missing = [
        body
        for sender, recipient, body in expected
        if body not in received_by.get((sender, recipient), [])
    ]
    assert missing == [], f"missing after relay kill/resume: {missing[:10]}"


def test_receipts_stuck_until_relay_returns(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.alice.send("bob", "needs receipt")
    mesh.bob.fetch("alice", send_receipts=False)
    assert mesh.alice.pending_count("bob") == 1

    mesh.stop_all_relays()
    mesh.bob.flush_receipts("alice")
    msgs, err = mesh.alice.try_fetch("bob", send_receipts=False, save_local=False)
    assert err is None
    assert msgs == []

    mesh.start_all_relays()
    mesh.bob.flush_receipts("alice")
    mesh.alice.drain_receipts()
    assert mesh.alice.pending_count("bob") == 0


def test_aggressive_outage_during_full_schedule(charlie_mesh) -> None:
    """Kill relay at random points; recover with fetch + resend_pending."""
    mesh = charlie_mesh
    participants = {
        "alice": mesh.alice,
        "bob": mesh.bob,
        "charlie": mesh.charlie,
    }
    expected: list[tuple[str, str, str]] = []
    kill_at = {17, 42, 68, 91}

    for idx, (sender, recipient, count) in enumerate(build_send_schedule()):
        if idx in kill_at:
            mesh.stop_relay()
        party = participants[sender]
        for i in range(count):
            body = f"agg-{idx}-{i}:{sender}->{recipient}"
            party.try_send(recipient, body)
            expected.append((sender, recipient, body))
            if idx in kill_at and i == count // 2:
                mesh.start_all_relays()

    mesh.start_all_relays()
    for _round in range(2):
        for party in participants.values():
            for peer in party.store.list_contacts():
                party.fetch(peer, send_receipts=True)
            party.drain_receipts()
            for peer in party.store.list_contacts():
                party.resend_pending(peer)

    received_by: dict[tuple[str, str], list[str]] = {}
    for recipient_name, party in participants.items():
        for sender_name in party.store.list_contacts():
            bodies = [
                body
                for _seq, body in party.store.list_inbound_messages(sender_name, party.identity)
            ]
            received_by[(sender_name, recipient_name)] = bodies

    missing = [
        body
        for sender, recipient, body in expected
        if body not in received_by.get((sender, recipient), [])
    ]
    assert missing == [], f"aggressive outage missing {len(missing)}: {missing[:5]}"


def test_failed_send_without_resend_never_arrives(charlie_mesh) -> None:
    """When all relays are down, pending is saved but blob never reaches any relay."""
    mesh = charlie_mesh
    mesh.stop_all_relays()
    mesh.alice.try_send("bob", "orphan")

    mesh.start_all_relays()
    got = mesh.bob.fetch("alice", send_receipts=True)
    assert got == []
    assert mesh.alice.pending_count("bob") == 1



def test_pairing_fails_cleanly_when_relay_down(charlie_mesh) -> None:
    mesh = charlie_mesh
    mesh.stop_relay()

    from yakr_core.invite import create_invite, invite_to_url
    from yakr_cli.relay_pairing import inviter_wait_on_relay

    invite = create_invite(mesh.alice.identity, rendezvous_hint=mesh.relay_url)
    with pytest.raises(Exception):
        inviter_wait_on_relay(
            mesh.relay_url,
            mesh.alice.identity,
            invite,
            timeout_secs=2.0,
        )

