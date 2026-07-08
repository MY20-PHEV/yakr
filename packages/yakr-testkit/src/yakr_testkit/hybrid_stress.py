"""Random Alice↔Bob stress with concurrent fetch-all polling."""

from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass, field

from yakr_testkit.hybrid_homelab_mesh import HybridHomelabMesh
from yakr_testkit.mesh_client import MeshParticipant


@dataclass
class SentEvent:
    index: int
    sender: str
    recipient: str
    body: str
    sent_at_ms: int


@dataclass
class HybridStressResult:
    total_sent: int
    sent_events: list[SentEvent]
    missing_inbound: list[str]
    alice_pending: int
    bob_pending: int
    alice_history: list[str]
    bob_history: list[str]
    expected_global: list[str]
    fetch_errors: list[str] = field(default_factory=list)


def _body_send_index(body: str) -> int | None:
    """Extract hNNN send index from stress-test bodies, if present."""
    if body.startswith("h") and len(body) >= 4 and body[1:4].isdigit():
        return int(body[1:4])
    return None


def _conversation_history(
    viewer: MeshParticipant,
    peer: str,
) -> list[tuple[int, str, bool]]:
    """Merge outbound + inbound for one peer thread, sorted by send order then time."""
    rows: list[tuple[int, str, bool]] = []
    for seq, body, created_at in viewer.store.list_sent_messages_timed(peer):
        rows.append((created_at, body, True))
    for seq, body, received_at in viewer.store.list_inbound_messages_timed(peer, viewer.identity):
        rows.append((received_at, body, False))

    def _sort_key(item: tuple[int, str, bool]) -> tuple[int, int, int]:
        at, body, outbound = item
        send_index = _body_send_index(body)
        if send_index is not None:
            return (send_index, at, int(outbound))
        return (1 << 30, at, int(outbound))

    rows.sort(key=_sort_key)
    return rows


def _history_bodies(rows: list[tuple[int, str, bool]]) -> list[str]:
    return [body for _at, body, _outbound in rows]


def run_hybrid_alice_bob_stress(
    mesh: HybridHomelabMesh,
    *,
    total_messages: int = 100,
    fetch_interval_secs: tuple[float, float] = (1.0, 3.0),
    seed: int | None = None,
    send_burst_max: int = 4,
) -> HybridStressResult:
    """Send random bursts between Alice and Bob while both poll fetch-all every 1–3s."""
    rng = random.Random(seed)
    alice = mesh.alice
    bob = mesh.bob
    os.environ["YAKR_RELAYS_FILE"] = str(mesh.relays_file)
    stop = threading.Event()
    fetch_errors: list[str] = []
    lock_alice = threading.Lock()
    lock_bob = threading.Lock()
    sent_events: list[SentEvent] = []

    def _fetch_loop(participant: MeshParticipant, peer_lock: threading.Lock) -> None:
        while not stop.is_set():
            try:
                with peer_lock:
                    participant.fetch_all(send_receipts=True)
            except Exception as exc:
                fetch_errors.append(f"{participant.name} fetch: {exc}")
            if stop.wait(timeout=rng.uniform(*fetch_interval_secs)):
                break

    alice_thread = threading.Thread(
        target=_fetch_loop, args=(alice, lock_alice), name="alice-fetch", daemon=True
    )
    bob_thread = threading.Thread(
        target=_fetch_loop, args=(bob, lock_bob), name="bob-fetch", daemon=True
    )
    alice_thread.start()
    bob_thread.start()

    msg_index = 0
    while msg_index < total_messages:
        sender = alice if rng.random() < 0.5 else bob
        recipient = "bob" if sender is alice else "alice"
        burst = rng.randint(1, min(send_burst_max, total_messages - msg_index))
        peer_lock = lock_alice if sender is alice else lock_bob
        with peer_lock:
            for _ in range(burst):
                body = f"h{msg_index:03d}:{sender.name}->{recipient}"
                sender.send(recipient, body)
                sent_events.append(
                    SentEvent(
                        index=msg_index,
                        sender=sender.name,
                        recipient=recipient,
                        body=body,
                        sent_at_ms=int(time.time() * 1000),
                    )
                )
                msg_index += 1
        time.sleep(rng.uniform(0.01, 0.08))

    stop.set()
    alice_thread.join(timeout=30)
    bob_thread.join(timeout=30)

    with lock_alice:
        alice.flush_receipts()
        alice.fetch_all(send_receipts=True)
        alice.drain_receipts()
    with lock_bob:
        bob.flush_receipts()
        bob.fetch_all(send_receipts=True)
        bob.drain_receipts()

    for _ in range(20):
        with lock_alice:
            alice.fetch_all(send_receipts=True)
            alice.drain_receipts()
        with lock_bob:
            bob.fetch_all(send_receipts=True)
            bob.flush_receipts()
        if alice.pending_count() == 0 and bob.pending_count() == 0:
            break
        time.sleep(0.1)

    expected_by_recipient: dict[str, list[str]] = {"alice": [], "bob": []}
    for event in sent_events:
        expected_by_recipient[event.recipient].append(event.body)

    missing: list[str] = []
    for event in sent_events:
        recipient = alice if event.recipient == "alice" else bob
        peer = "bob" if event.recipient == "alice" else "alice"
        bodies = [
            body
            for _seq, body in recipient.store.list_inbound_messages(peer, recipient.identity)
        ]
        if event.body not in bodies:
            missing.append(event.body)

    alice_rows = _conversation_history(alice, "bob")
    bob_rows = _conversation_history(bob, "alice")
    alice_history = _history_bodies(alice_rows)
    bob_history = _history_bodies(bob_rows)
    expected_global = [event.body for event in sent_events]

    return HybridStressResult(
        total_sent=len(sent_events),
        sent_events=sent_events,
        missing_inbound=missing,
        alice_pending=alice.pending_count(),
        bob_pending=bob.pending_count(),
        alice_history=alice_history,
        bob_history=bob_history,
        expected_global=expected_global,
        fetch_errors=fetch_errors,
    )


def assert_hybrid_stress_passed(result: HybridStressResult) -> None:
    if result.fetch_errors:
        raise AssertionError(f"fetch errors: {result.fetch_errors[:5]}")
    if result.missing_inbound:
        raise AssertionError(f"missing inbound: {result.missing_inbound[:10]}")
    if result.alice_pending != 0 or result.bob_pending != 0:
        raise AssertionError(
            f"pending receipts: alice={result.alice_pending} bob={result.bob_pending}"
        )
    if result.alice_history != result.expected_global:
        first = next(
            (i for i, (a, e) in enumerate(zip(result.alice_history, result.expected_global)) if a != e),
            None,
        )
        detail = ""
        if first is not None:
            detail = f" at {first}: {result.alice_history[first]!r} vs {result.expected_global[first]!r}"
        raise AssertionError(
            f"alice history mismatch{detail} "
            f"(got {len(result.alice_history)} expected {len(result.expected_global)})"
        )
    if result.bob_history != result.expected_global:
        first = next(
            (i for i, (a, e) in enumerate(zip(result.bob_history, result.expected_global)) if a != e),
            None,
        )
        detail = ""
        if first is not None:
            detail = f" at {first}: {result.bob_history[first]!r} vs {result.expected_global[first]!r}"
        raise AssertionError(
            f"bob history mismatch{detail} "
            f"(got {len(result.bob_history)} expected {len(result.expected_global)})"
        )
