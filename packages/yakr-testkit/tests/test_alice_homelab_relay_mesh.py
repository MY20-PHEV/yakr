"""Five-peer mesh stress with mid-test Alice homelab relay activation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yakr_testkit.five_peer_mesh import (
  activate_alice_homelab_relay,
  assert_five_peer_trust_model,
  build_five_peer_mesh,
  five_peer_homelab_configured,
  relay_blob_count,
)
from yakr_testkit.five_peer_stress import (
  assert_alice_bob_histories_match,
  assert_five_peer_stress_passed,
  run_five_peer_stress,
)


@pytest.fixture
def five_peer_mesh(tmp_path: Path):
  previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
  previous_name = os.environ.pop("YAKR_RELAY_NAME", None)
  mesh = build_five_peer_mesh(tmp_path)
  try:
    yield mesh
  finally:
    mesh.stop()
    if previous_relay is None:
      os.environ.pop("YAKR_RELAY_URL", None)
    else:
      os.environ["YAKR_RELAY_URL"] = previous_relay
    if previous_name is None:
      os.environ.pop("YAKR_RELAY_NAME", None)
    else:
      os.environ["YAKR_RELAY_NAME"] = previous_name


def test_five_peer_trust_model(five_peer_mesh) -> None:
  assert_five_peer_trust_model(five_peer_mesh)


def test_alice_homelab_relay_mid_mesh(five_peer_mesh, tmp_path: Path) -> None:
  """Alice, Bob, Charlie, Dennis, Geoff — Alice brings up alice-ops mid-test."""
  mesh = five_peer_mesh

  phase1 = run_five_peer_stress(mesh, total_messages=36, start_index=0, seed=11)
  assert_five_peer_stress_passed(phase1)

  alice_ops = activate_alice_homelab_relay(mesh, tmp_path)
  assert mesh.alice.store.get_contact("alice-ops") is not None
  alice_profile = mesh.alice.store.load_local_profile()
  assert alice_profile is not None
  relay_names = {descriptor.name for descriptor in alice_profile.relay_descriptors}
  assert "alice-ops" in relay_names

  # Charlie + Dennis down — traffic must flow via alice-ops (and geoff's relay).
  mesh.charlie_relay.stop()
  mesh.dennis_relay.stop()

  phase2 = run_five_peer_stress(mesh, total_messages=36, start_index=36, seed=22)
  assert_five_peer_stress_passed(phase2)

  assert relay_blob_count(alice_ops) > 0

  all_events = phase1.sent_events + phase2.sent_events
  alice_bob_bodies = [
    event.body
    for event in all_events
    if {event.sender, event.recipient} == {"alice", "bob"}
  ]
  assert_alice_bob_histories_match(mesh, alice_bob_bodies)

  # Geoff received post-relay traffic from Alice.
  geoff_from_alice = [
    event.body
    for event in phase2.sent_events
    if event.sender == "alice" and event.recipient == "geoff"
  ]
  for body in geoff_from_alice:
    inbound = [b for _s, b in mesh.geoff.store.list_inbound_messages("alice", mesh.geoff.identity)]
    assert body in inbound


@pytest.fixture
def five_peer_mesh_live(tmp_path: Path):
  if not five_peer_homelab_configured():
    pytest.skip(
      "set CHARLIE_URL, DENNIS_URL, and ALICE_OPS_VPS_HOST (or VPS_HOST) for live five-peer test"
    )
  previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
  previous_name = os.environ.pop("YAKR_RELAY_NAME", None)
  mesh = build_five_peer_mesh(tmp_path, live=True)
  try:
    yield mesh
  finally:
    mesh.stop()
    if previous_relay is None:
      os.environ.pop("YAKR_RELAY_URL", None)
    else:
      os.environ["YAKR_RELAY_URL"] = previous_relay
    if previous_name is None:
      os.environ.pop("YAKR_RELAY_NAME", None)
    else:
      os.environ["YAKR_RELAY_NAME"] = previous_name


@pytest.mark.homelab
def test_alice_homelab_relay_mid_mesh_live(five_peer_mesh_live, tmp_path: Path) -> None:
  """Live variant: alice-ops deploys to the same homelab VPS as Charlie and Dennis."""
  mesh = five_peer_mesh_live
  if not mesh.charlie_relay.vps_host or not mesh.dennis_relay.vps_host:
    pytest.skip("set CHARLIE_VPS_HOST / DENNIS_VPS_HOST (or VPS_HOST) for relay stop/start")

  phase1 = run_five_peer_stress(mesh, total_messages=36, start_index=0, seed=11)
  assert_five_peer_stress_passed(phase1)

  alice_ops = activate_alice_homelab_relay(mesh, tmp_path, live=True)
  assert mesh.alice.store.get_contact("alice-ops") is not None
  alice_profile = mesh.alice.store.load_local_profile()
  assert alice_profile is not None
  relay_names = {descriptor.name for descriptor in alice_profile.relay_descriptors}
  assert "alice-ops" in relay_names

  mesh.charlie_relay.stop()
  mesh.dennis_relay.stop()
  try:
    phase2 = run_five_peer_stress(mesh, total_messages=36, start_index=36, seed=22)
    assert_five_peer_stress_passed(phase2)

    blob_count = relay_blob_count(alice_ops)
    assert blob_count > 0, f"expected blobs on homelab alice-ops, got count={blob_count}"

    all_events = phase1.sent_events + phase2.sent_events
    alice_bob_bodies = [
      event.body
      for event in all_events
      if {event.sender, event.recipient} == {"alice", "bob"}
    ]
    assert_alice_bob_histories_match(mesh, alice_bob_bodies)
  finally:
    mesh.dennis_relay.start()
    mesh.charlie_relay.start()
