"""Delivery profile replay and rollback protection tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from yakr_core.delivery_profile import (
    DeliveryProfile,
    accept_delivery_profile_update,
    apply_delivery_profile_update,
    create_delivery_profile,
)
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_accept_delivery_profile_update_rejects_rollback() -> None:
    alice = Identity.generate("alice")
    current = create_delivery_profile(alice, relay_descriptors=[], version=3)
    replay = create_delivery_profile(alice, relay_descriptors=[], version=1)
    with pytest.raises(ValueError, match="rollback"):
        accept_delivery_profile_update(current, replay)


def test_accept_delivery_profile_update_allows_same_version() -> None:
    alice = Identity.generate("alice")
    profile = create_delivery_profile(alice, relay_descriptors=[], version=2)
    accept_delivery_profile_update(profile, profile)


def test_apply_delivery_profile_update_rejects_rollback_on_contact() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    contact.delivery_profile = create_delivery_profile(bob, relay_descriptors=[], version=2)
    replay = create_delivery_profile(bob, relay_descriptors=[], version=1)
    with pytest.raises(ValueError, match="rollback"):
        apply_delivery_profile_update(contact, replay, bob.signing_public_bytes)


def test_decrypt_replayed_profile_consumes_seq_without_rollback(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        bob_contact = mesh.bob.store.get_contact("alice")
        assert bob_contact is not None
        v2 = create_delivery_profile(mesh.alice.identity, relay_descriptors=[], version=2)
        bob_contact.delivery_profile = v2
        mesh.bob.store.save_contact(bob_contact)
        before_seq = bob_contact.last_recv_seq

        alice_contact = mesh.alice.store.get_contact("bob")
        assert alice_contact is not None
        replay = create_delivery_profile(mesh.alice.identity, relay_descriptors=[], version=1)
        encrypted = Session(mesh.alice.identity, alice_contact).encrypt_profile(replay)

        bob_session = Session(mesh.bob.identity, bob_contact)
        inner = bob_session.decrypt_outer(encrypted.outer_blob)
        profile = DeliveryProfile.from_b64(inner.body)
        with pytest.raises(ValueError, match="rollback"):
            apply_delivery_profile_update(bob_contact, profile, bob_contact.signing_public)
        mesh.bob.store.save_contact(bob_contact)

        updated = mesh.bob.store.get_contact("alice")
        assert updated is not None
        assert updated.delivery_profile is not None
        assert updated.delivery_profile.version == 2
        assert updated.last_recv_seq == before_seq + 1
    finally:
        mesh.stop()
