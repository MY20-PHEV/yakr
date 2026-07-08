"""Hybrid homelab mesh: local Charlie + remote Dennis, Alice↔Bob stress (single-hop)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from yakr_core.delivery_profile import create_delivery_profile, relay_descriptor_for_operator
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.relay import RelayNode, save_relay_network
from yakr_core.store import FileLocalStore
from yakr_testkit.homelab_mesh import RemoteRelayHandle, _wrap_secret
from yakr_testkit.mesh_client import MeshParticipant
from yakr_testkit.mesh_setup import CharlieMesh, RelayHandle, build_charlie_mesh


def hybrid_live_configured() -> bool:
    """True when a homelab Dennis relay URL is set (Charlie may be local in-process)."""
    return bool(os.environ.get("DENNIS_URL", "").strip())


def _write_shared_relays(
    alice_store: FileLocalStore,
    bob_store: FileLocalStore,
    *,
    charlie_url: str,
    charlie_wrap: bytes,
    dennis_url: str,
    dennis_wrap: bytes,
) -> Path:
    network = {
        "charlie": RelayNode("charlie", "both", charlie_url.rstrip("/"), charlie_wrap),
        "dennis": RelayNode("dennis", "both", dennis_url.rstrip("/"), dennis_wrap),
    }
    for store in (alice_store, bob_store):
        shared = store.root / "shared"
        shared.mkdir(parents=True, exist_ok=True)
        save_relay_network(shared / "relays.json", network)
    return alice_store.root / "shared" / "relays.json"


def _operator_identity(home: Path, name: str) -> Identity:
    identity_path = home / "identity.json"
    if identity_path.exists():
        return Identity.load(identity_path)
    home.mkdir(parents=True, exist_ok=True)
    identity = Identity.generate(name)
    identity.save(identity_path)
    return identity


def _upgrade_charlie_mesh_to_hybrid(
    mesh: CharlieMesh,
    *,
    charlie_wrap: bytes,
    dennis_wrap: bytes,
) -> tuple[Path, str, str]:
    """Apply hybrid topology: Bob↔Dennis operator, shared relays.json, single-hop relays."""
    charlie_url = mesh.charlie_relay.relay_url
    dennis_url = mesh.dennis_relay.relay_url
    charlie = mesh.charlie.identity
    dennis = mesh.dennis.identity
    alice = mesh.alice.identity
    bob = mesh.bob.identity

    charlie_descriptor = relay_descriptor_for_operator(
        charlie, "both", charlie_url, charlie_wrap
    )
    dennis_descriptor = relay_descriptor_for_operator(dennis, "both", dennis_url, dennis_wrap)

    charlie_profile = create_delivery_profile(charlie, relay_descriptors=[charlie_descriptor])
    mesh.charlie.store.save_local_profile(charlie_profile)
    charlie_contact = mesh.alice.store.get_contact("charlie")
    if charlie_contact is not None:
        charlie_contact.delivery_profile = charlie_profile
        mesh.alice.store.save_contact(charlie_contact)

    dennis_profile = create_delivery_profile(dennis, relay_descriptors=[dennis_descriptor])
    mesh.dennis.store.save_local_profile(dennis_profile)
    dennis_contact = mesh.alice.store.get_contact("dennis")
    if dennis_contact is not None:
        dennis_contact.delivery_profile = dennis_profile
        mesh.alice.store.save_contact(dennis_contact)

    bob_dennis = Contact.establish(bob, "dennis", export_public_bundle(dennis))
    bob_dennis.delivery_profile = dennis_profile
    mesh.bob.store.save_contact(bob_dennis)
    dennis_bob = Contact.establish(dennis, "bob", export_public_bundle(bob))
    mesh.dennis.store.save_contact(dennis_bob)

    alice_profile = create_delivery_profile(
        alice,
        relay_descriptors=[charlie_descriptor, dennis_descriptor],
    )
    mesh.alice.store.save_local_profile(alice_profile)
    bob_alice = mesh.bob.store.get_contact("alice")
    if bob_alice is not None:
        bob_alice.delivery_profile = alice_profile
        mesh.bob.store.save_contact(bob_alice)

    bob_profile = create_delivery_profile(bob, relay_descriptors=[dennis_descriptor])
    mesh.bob.store.save_local_profile(bob_profile)

    relays_file = _write_shared_relays(
        mesh.alice.store,
        mesh.bob.store,
        charlie_url=charlie_url,
        charlie_wrap=charlie_wrap,
        dennis_url=dennis_url,
        dennis_wrap=dennis_wrap,
    )
    mesh.bob.relay_url = dennis_url
    return relays_file, charlie_url, dennis_url


@dataclass
class HybridHomelabMesh:
    """Alice (local) and Bob (homelab relay path) with Charlie + Dennis single-hop relays."""

    charlie_relay: RelayHandle | RemoteRelayHandle
    dennis_relay: RelayHandle | RemoteRelayHandle
    alice: MeshParticipant
    bob: MeshParticipant
    charlie: MeshParticipant
    dennis: MeshParticipant
    relays_file: Path

    def stop(self) -> None:
        if isinstance(self.charlie_relay, RelayHandle) and self.charlie_relay.local:
            self.charlie_relay.stop()
        if isinstance(self.dennis_relay, RelayHandle) and self.dennis_relay.local:
            self.dennis_relay.stop()


def build_hybrid_homelab_mesh(tmp_path: Path, *, live: bool = False) -> HybridHomelabMesh:
    """Build hybrid mesh for Alice↔Bob stress tests."""
    os.environ["YAKR_REQUIRE_TLS"] = "1"

    if not live:
        base = build_charlie_mesh(tmp_path)
        relays_file, charlie_url, dennis_url = _upgrade_charlie_mesh_to_hybrid(
            base,
            charlie_wrap=base.charlie_relay.wrap_secret,
            dennis_wrap=base.dennis_relay.wrap_secret,
        )
        return HybridHomelabMesh(
            charlie_relay=base.charlie_relay,
            dennis_relay=base.dennis_relay,
            alice=base.alice,
            bob=base.bob,
            charlie=base.charlie,
            dennis=base.dennis,
            relays_file=relays_file,
        )

    from yakr_testkit.homelab_mesh import build_homelab_mesh

    base = build_homelab_mesh(tmp_path)
    relays_file, charlie_url, dennis_url = _upgrade_charlie_mesh_to_hybrid(
        base,
        charlie_wrap=base.charlie_relay.wrap_secret,
        dennis_wrap=base.dennis_relay.wrap_secret,
    )
    base.bob.relay_url = dennis_url
    return HybridHomelabMesh(
        charlie_relay=base.charlie_relay,
        dennis_relay=base.dennis_relay,
        alice=base.alice,
        bob=base.bob,
        charlie=base.charlie,
        dennis=base.dennis,
        relays_file=relays_file,
    )


def assert_hybrid_trust_model(mesh: HybridHomelabMesh) -> None:
    """Bob is paired with Dennis (relay); learns Charlie only via Alice's profile."""
    assert mesh.alice.store.get_contact("bob") is not None
    assert mesh.alice.store.get_contact("charlie") is not None
    assert mesh.alice.store.get_contact("dennis") is not None
    assert mesh.bob.store.get_contact("alice") is not None
    assert mesh.bob.store.get_contact("dennis") is not None
    assert mesh.bob.store.get_contact("charlie") is None
