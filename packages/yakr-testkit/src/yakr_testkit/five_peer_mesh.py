"""Five-peer mesh (Alice, Bob, Charlie, Dennis, Geoff) with mid-test Alice homelab relay."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path

from yakr_core.delivery_profile import create_delivery_profile, relay_descriptor_for_operator
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.profile_ack import apply_peer_profile_ack
from yakr_core.relay_authorization import authorized_publish_relays
from yakr_core.relay_operator import (
    create_relay_operator,
    refresh_operator_public_url,
    relay_operator_home,
)
from yakr_core.store import FileLocalStore
from yakr_testkit.hybrid_homelab_mesh import HybridHomelabMesh, build_hybrid_homelab_mesh
from yakr_testkit.mesh_client import MeshParticipant
from yakr_testkit.mesh_setup import RelayHandle, _start_relay_server


@dataclass
class FivePeerMesh(HybridHomelabMesh):
  geoff: MeshParticipant
  geoff_relay: RelayHandle
  alice_ops_relay: RelayHandle | None = None

  def stop(self) -> None:
    if self.alice_ops_relay is not None and self.alice_ops_relay.local:
      self.alice_ops_relay.stop()
    if self.geoff_relay.local:
      self.geoff_relay.stop()
    super().stop()


def _pair_peer(
  local: Identity,
  local_store: FileLocalStore,
  remote: Identity,
  remote_store: FileLocalStore,
  *,
  remote_profile=None,
) -> None:
  local_remote = Contact.establish(local, remote.name, export_public_bundle(remote))
  if remote_profile is not None:
    local_remote.delivery_profile = remote_profile
  local_store.save_contact(local_remote)

  remote_local = Contact.establish(remote, local.name, export_public_bundle(local))
  remote_local_profile = remote_store.load_local_profile()
  if remote_local_profile is not None:
    remote_local.delivery_profile = remote_local_profile
  remote_store.save_contact(remote_local)


def _add_geoff(tmp_path: Path, mesh: HybridHomelabMesh) -> tuple[MeshParticipant, RelayHandle]:
  geoff = Identity.generate("geoff")
  geoff_wrap = secrets.token_bytes(32)
  geoff_relay = _start_relay_server(
    tmp_path / "relay-geoff",
    tmp_path / "pairing-geoff",
    geoff_wrap,
    identity=geoff,
    name="geoff",
  )
  geoff_store = FileLocalStore(tmp_path / "geoff")
  geoff_store.save_identity(geoff)

  geoff_descriptor = relay_descriptor_for_operator(
    geoff, "both", geoff_relay.relay_url, geoff_wrap
  )
  geoff_profile = create_delivery_profile(geoff, relay_descriptors=[geoff_descriptor])
  geoff_store.save_local_profile(geoff_profile)

  alice_profile = mesh.alice.store.load_local_profile()
  bob_profile = mesh.bob.store.load_local_profile()

  _pair_peer(geoff, geoff_store, mesh.alice.identity, mesh.alice.store, remote_profile=alice_profile)
  _pair_peer(geoff, geoff_store, mesh.bob.identity, mesh.bob.store, remote_profile=bob_profile)
  _pair_peer(mesh.alice.identity, mesh.alice.store, geoff, geoff_store, remote_profile=geoff_profile)
  _pair_peer(mesh.bob.identity, mesh.bob.store, geoff, geoff_store, remote_profile=geoff_profile)

  geoff_alice = geoff_store.get_contact("alice")
  if geoff_alice is not None and alice_profile is not None:
    apply_peer_profile_ack(geoff_alice, alice_profile)
    geoff_store.save_contact(geoff_alice)

  participant = MeshParticipant("geoff", geoff, geoff_store, geoff_relay.relay_url)
  return participant, geoff_relay


def build_five_peer_mesh(tmp_path: Path) -> FivePeerMesh:
  base = build_hybrid_homelab_mesh(tmp_path, live=False)
  geoff, geoff_relay = _add_geoff(tmp_path, base)
  return FivePeerMesh(
    charlie_relay=base.charlie_relay,
    dennis_relay=base.dennis_relay,
    alice=base.alice,
    bob=base.bob,
    charlie=base.charlie,
    dennis=base.dennis,
    relays_file=base.relays_file,
    geoff=geoff,
    geoff_relay=geoff_relay,
  )


def republish_alice_profile(mesh: FivePeerMesh) -> None:
  contacts = [
    contact
    for name in mesh.alice.store.list_contacts()
    if (contact := mesh.alice.store.get_contact(name)) is not None
  ]
  authorized = authorized_publish_relays(
    identity_name=mesh.alice.identity.name,
    contacts=contacts,
  )
  previous = mesh.alice.store.load_local_profile()
  version = (previous.version + 1) if previous is not None else 1
  profile = create_delivery_profile(
    mesh.alice.identity,
    relay_descriptors=authorized,
    version=version,
  )
  mesh.alice.store.save_local_profile(profile)

  for peer_name in mesh.alice.store.list_contacts():
    peer_contact = mesh.alice.store.get_contact(peer_name)
    if peer_contact is None:
      continue
    apply_peer_profile_ack(peer_contact, profile)
    mesh.alice.store.save_contact(peer_contact)

  for participant in (mesh.bob, mesh.geoff, mesh.charlie, mesh.dennis):
    peer_contact = participant.store.get_contact("alice")
    if peer_contact is None:
      continue
    peer_contact.delivery_profile = profile
    participant.store.save_contact(peer_contact)


def activate_alice_homelab_relay(mesh: FivePeerMesh, tmp_path: Path) -> RelayHandle:
  """Alice spins up alice-ops relay mid-mesh and republishes her profile."""
  operator_home = relay_operator_home(mesh.alice.store.root, "alice-ops")
  bundle = create_relay_operator(
    mesh.alice.store,
    operator_name="alice-ops",
    public_url="https://127.0.0.1:65530",
    force=operator_home.exists(),
  )
  operator = bundle.operator_store.load_identity()
  assert operator is not None

  relay = _start_relay_server(
    tmp_path / "relay-alice-ops",
    tmp_path / "pairing-alice-ops",
    bundle.manifest.wrap_secret,
    identity=operator,
    name="alice-ops",
  )
  refresh_operator_public_url(
    bundle.operator_home,
    mesh.alice.store,
    relay.relay_url,
  )
  republish_alice_profile(mesh)
  mesh.alice_ops_relay = relay
  return relay


def assert_five_peer_trust_model(mesh: FivePeerMesh) -> None:
  assert mesh.alice.store.get_contact("bob") is not None
  assert mesh.alice.store.get_contact("geoff") is not None
  assert mesh.alice.store.get_contact("charlie") is not None
  assert mesh.alice.store.get_contact("dennis") is not None
  assert mesh.bob.store.get_contact("alice") is not None
  assert mesh.bob.store.get_contact("geoff") is not None
  assert mesh.bob.store.get_contact("dennis") is not None
  assert mesh.bob.store.get_contact("charlie") is None
  assert mesh.geoff.store.get_contact("alice") is not None
  assert mesh.geoff.store.get_contact("bob") is not None
  assert mesh.geoff.store.get_contact("charlie") is None


def relay_blob_count(relay: RelayHandle) -> int:
  import sqlite3

  db = relay.relay_data_path / "relay.db"
  if not db.exists():
    return 0
  with sqlite3.connect(db) as conn:
    row = conn.execute("SELECT COUNT(*) FROM blobs").fetchone()
  return int(row[0]) if row else 0
