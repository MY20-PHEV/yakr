"""Stress messaging across Alice, Bob, and Geoff with concurrent fetch-all."""

from __future__ import annotations

import os
import random
import threading
import time
from dataclasses import dataclass, field

from yakr_testkit.five_peer_mesh import FivePeerMesh
from yakr_testkit.hybrid_stress import (
    HybridStressResult,
    SentEvent,
    _body_send_index,
    _conversation_history,
    _history_bodies,
    assert_hybrid_stress_passed,
)
from yakr_testkit.mesh_client import MeshParticipant


PEERS = ("alice", "bob", "geoff")


@dataclass
class FivePeerStressResult:
  total_sent: int
  sent_events: list[SentEvent]
  missing_inbound: list[str]
  pending: dict[str, int]
  histories: dict[str, list[str]]
  expected_global: list[str]
  fetch_errors: list[str] = field(default_factory=list)


def _participant(mesh: FivePeerMesh, name: str) -> MeshParticipant:
  return getattr(mesh, name)


def run_five_peer_stress(
  mesh: FivePeerMesh,
  *,
  total_messages: int = 60,
  start_index: int = 0,
  fetch_interval_secs: tuple[float, float] = (0.05, 0.15),
  seed: int | None = None,
) -> FivePeerStressResult:
  rng = random.Random(seed)
  participants = [_participant(mesh, name) for name in PEERS]
  locks = {name: threading.Lock() for name in PEERS}
  os.environ["YAKR_RELAYS_FILE"] = str(mesh.relays_file)
  stop = threading.Event()
  fetch_errors: list[str] = []
  sent_events: list[SentEvent] = []

  def _fetch_loop(participant: MeshParticipant) -> None:
    while not stop.is_set():
      try:
        with locks[participant.name]:
          participant.fetch_all(send_receipts=True)
      except Exception as exc:
        fetch_errors.append(f"{participant.name} fetch: {exc}")
      if stop.wait(timeout=rng.uniform(*fetch_interval_secs)):
        break

  threads = [
    threading.Thread(
      target=_fetch_loop,
      args=(participant,),
      name=f"{participant.name}-fetch",
      daemon=True,
    )
    for participant in participants
  ]
  for thread in threads:
    thread.start()

  msg_index = start_index
  while msg_index < start_index + total_messages:
    sender_name, recipient_name = rng.sample(PEERS, 2)
    sender = _participant(mesh, sender_name)
    burst = rng.randint(1, min(3, start_index + total_messages - msg_index))
    with locks[sender_name]:
      for _ in range(burst):
        body = f"h{msg_index:03d}:{sender_name}->{recipient_name}"
        sender.send(recipient_name, body)
        sent_events.append(
          SentEvent(
            index=msg_index,
            sender=sender_name,
            recipient=recipient_name,
            body=body,
            sent_at_ms=int(time.time() * 1000),
          )
        )
        msg_index += 1
    time.sleep(rng.uniform(0.01, 0.06))

  stop.set()
  for thread in threads:
    thread.join(timeout=30)

  for participant in participants:
    with locks[participant.name]:
      participant.flush_receipts()
      participant.fetch_all(send_receipts=True)
      participant.drain_receipts()

  for _ in range(20):
    for participant in participants:
      with locks[participant.name]:
        participant.fetch_all(send_receipts=True)
        participant.drain_receipts()
    if all(_participant(mesh, name).pending_count() == 0 for name in PEERS):
      break
    time.sleep(0.1)

  missing: list[str] = []
  for event in sent_events:
    recipient = _participant(mesh, event.recipient)
    bodies = [
      body
      for _seq, body in recipient.store.list_inbound_messages(
        event.sender, recipient.identity
      )
    ]
    if event.body not in bodies:
      missing.append(event.body)

  histories: dict[str, list[str]] = {}
  for viewer_name, peer_name in (("alice", "bob"), ("bob", "alice"), ("geoff", "alice")):
    viewer = _participant(mesh, viewer_name)
    rows = _conversation_history(viewer, peer_name)
    histories[f"{viewer_name}:{peer_name}"] = _history_bodies(rows)

  expected_alice_bob = [
    event.body for event in sent_events if {event.sender, event.recipient} == {"alice", "bob"}
  ]

  return FivePeerStressResult(
    total_sent=len(sent_events),
    sent_events=sent_events,
    missing_inbound=missing,
    pending={name: _participant(mesh, name).pending_count() for name in PEERS},
    histories=histories,
    expected_global=expected_alice_bob,
    fetch_errors=fetch_errors,
  )


def assert_five_peer_stress_passed(result: FivePeerStressResult) -> None:
  if result.fetch_errors:
    raise AssertionError(f"fetch errors: {result.fetch_errors[:5]}")
  if result.missing_inbound:
    raise AssertionError(f"missing inbound: {result.missing_inbound[:10]}")
  for name, count in result.pending.items():
    if count != 0:
      raise AssertionError(f"pending receipts for {name}: {count}")


def assert_alice_bob_histories_match(
  mesh: FivePeerMesh,
  expected_bodies: list[str],
) -> None:
  """Alice and Bob threads share the same ordered alice↔bob transcript."""
  hybrid = HybridStressResult(
    total_sent=len(expected_bodies),
    sent_events=[],
    missing_inbound=[],
    alice_pending=mesh.alice.pending_count(),
    bob_pending=mesh.bob.pending_count(),
    alice_history=_history_bodies(_conversation_history(mesh.alice, "bob")),
    bob_history=_history_bodies(_conversation_history(mesh.bob, "alice")),
    expected_global=expected_bodies,
    fetch_errors=[],
  )
  assert_hybrid_stress_passed(hybrid)
