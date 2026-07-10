"""Five-peer mesh (Alice, Bob, Charlie, Dennis, Geoff) with mid-test Alice homelab relay."""

from __future__ import annotations

import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from yakr_core.delivery_profile import create_delivery_profile, relay_descriptor_for_operator
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.profile_ack import apply_peer_profile_ack
from yakr_core.relay_authorization import authorized_publish_relays
from yakr_core.relay_deploy import (
    deploy_operator_bundle,
    resolve_alice_ops_public_url,
    resolve_alice_ops_vps_host,
    repo_root_from_here,
)
from yakr_core.relay_operator import (
    create_relay_operator,
    refresh_operator_public_url,
    relay_operator_home,
)
from yakr_core.store import FileLocalStore
from yakr_core.tls import endpoint_tls_spki_sha256
from yakr_testkit.homelab_mesh import RemoteRelayHandle, homelab_env_configured
from yakr_testkit.homelab_mesh import build_homelab_mesh as _build_homelab_mesh
from yakr_testkit.homelab_mesh import _remote_relay
from yakr_testkit.hybrid_homelab_mesh import (
    HybridHomelabMesh,
    build_hybrid_homelab_mesh,
    _upgrade_charlie_mesh_to_hybrid,
)
from yakr_testkit.mesh_client import MeshParticipant
from yakr_testkit.mesh_setup import RelayHandle, _start_relay_server, _wait_relay_healthy


@dataclass
class FivePeerMesh(HybridHomelabMesh):
    geoff: MeshParticipant
    geoff_relay: RelayHandle
    alice_ops_relay: RelayHandle | RemoteRelayHandle | None = None

    def stop(self) -> None:
        if self.alice_ops_relay is not None and getattr(self.alice_ops_relay, "local", False):
            self.alice_ops_relay.stop()
        if self.geoff_relay.local:
            self.geoff_relay.stop()
        super().stop()


def five_peer_homelab_configured() -> bool:
    return homelab_env_configured() and resolve_alice_ops_vps_host() is not None


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


def build_five_peer_mesh(tmp_path: Path, *, live: bool = False) -> FivePeerMesh:
    if live:
        base = _build_homelab_mesh(tmp_path)
        relays_file, _, dennis_url = _upgrade_charlie_mesh_to_hybrid(
            base,
            charlie_wrap=base.charlie_relay.wrap_secret,
            dennis_wrap=base.dennis_relay.wrap_secret,
        )
        base.bob.relay_url = dennis_url
        hybrid = HybridHomelabMesh(
            charlie_relay=base.charlie_relay,
            dennis_relay=base.dennis_relay,
            alice=base.alice,
            bob=base.bob,
            charlie=base.charlie,
            dennis=base.dennis,
            relays_file=relays_file,
        )
    else:
        hybrid = build_hybrid_homelab_mesh(tmp_path, live=False)
    geoff, geoff_relay = _add_geoff(tmp_path, hybrid)
    return FivePeerMesh(
        charlie_relay=hybrid.charlie_relay,
        dennis_relay=hybrid.dennis_relay,
        alice=hybrid.alice,
        bob=hybrid.bob,
        charlie=hybrid.charlie,
        dennis=hybrid.dennis,
        relays_file=hybrid.relays_file,
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


def activate_alice_homelab_relay(
    mesh: FivePeerMesh,
    tmp_path: Path,
    *,
    live: bool = False,
) -> RelayHandle | RemoteRelayHandle:
    """Alice spins up alice-ops relay mid-mesh and republishes her profile."""
    operator_home = relay_operator_home(mesh.alice.store.root, "alice-ops")
    host_port = int(os.environ.get("ALICE_OPS_PORT", "8092"))
    public_url = (
        resolve_alice_ops_public_url(host_port=host_port)
        if live
        else "https://127.0.0.1:65530"
    )

    bundle = create_relay_operator(
        mesh.alice.store,
        operator_name="alice-ops",
        public_url=public_url,
        host_port=host_port,
        force=operator_home.exists(),
    )
    operator = bundle.operator_store.load_identity()
    assert operator is not None

    if live:
        vps_host = resolve_alice_ops_vps_host()
        if not vps_host:
            raise ValueError("set ALICE_OPS_VPS_HOST or VPS_HOST for live alice-ops deploy")
        try:
            deploy_operator_bundle(
                mesh.alice.store,
                "alice-ops",
                vps_host,
                repo_root=repo_root_from_here(Path(__file__)),
                host_port=host_port,
            )
        except subprocess.CalledProcessError:
            pass  # deploy script may fail curl while container is still starting
        refresh_operator_public_url(operator_home, mesh.alice.store, public_url)
        _wait_relay_healthy(public_url, tls_spki=endpoint_tls_spki_sha256(operator))
        relay: RelayHandle | RemoteRelayHandle = _remote_relay(
            "alice-ops",
            public_url,
            bundle.manifest.wrap_secret,
            operator,
        )
        relay.container_name = os.environ.get("ALICE_OPS_CONTAINER", "yakr-alice-ops")
        if not relay.vps_host:
            relay.vps_host = vps_host
    else:
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


def relay_blob_count(relay: RelayHandle | RemoteRelayHandle) -> int:
    import sqlite3

    if isinstance(relay, RemoteRelayHandle):
        if not relay.vps_host or not relay.container_name:
            return -1
        import subprocess

        result = subprocess.run(
            [
                "ssh",
                relay.vps_host,
                f"docker exec {relay.container_name} "
                "python3 -c \"import sqlite3; c=sqlite3.connect('/data/relay.db'); "
                "print(c.execute('select count(*) from blobs').fetchone()[0])\"",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return -1
        return int(result.stdout.strip())

    db = relay.relay_data_path / "relay.db"
    if not db.exists():
        return 0
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT COUNT(*) FROM blobs").fetchone()
    return int(row[0]) if row else 0
