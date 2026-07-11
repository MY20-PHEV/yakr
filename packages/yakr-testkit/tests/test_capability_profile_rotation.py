"""Profile-carried capability generation and issuance salt."""

from __future__ import annotations

import secrets

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.capability_client import (
    capability_material_params,
    enrich_descriptor_capabilities,
)
from yakr_core.capability_grant import derive_capability_material, issue_capability_grant
from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.store import FileLocalStore


def test_relay_descriptor_roundtrips_capability_fields() -> None:
    descriptor = RelayDescriptor(
        name="relay",
        role="both",
        url="https://relay.example:8090",
        wrap_secret=secrets.token_bytes(32),
        tls_spki_sha256=secrets.token_bytes(32),
        capability_generation=2,
        capability_issuance_salt=secrets.token_bytes(16),
    )
    restored = RelayDescriptor.from_dict(descriptor.to_dict())
    assert restored.capability_generation == 2
    assert restored.capability_issuance_salt == descriptor.capability_issuance_salt


def test_enrich_descriptor_bumps_generation(tmp_path) -> None:
    alice = Identity.generate("alice")
    relay = Identity.generate("relay")
    store = FileLocalStore(tmp_path)
    store.save_identity(alice)
    contact = Contact.establish(alice, "relay", export_public_bundle(relay))
    store.save_contact(contact)

    descriptor = RelayDescriptor(
        name="relay",
        role="both",
        url="https://relay.example:8090",
        wrap_secret=secrets.token_bytes(32),
        tls_spki_sha256=secrets.token_bytes(32),
    )
    first = enrich_descriptor_capabilities(store, descriptor)
    assert first.capability_generation == 1
    assert len(first.capability_issuance_salt) == 16

    relay_issuance = ed25519.Ed25519PrivateKey.generate()
    tls_pin = first.tls_spki_sha256
    capability_id, auth_private = derive_capability_material(
        contact.master_secret,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=first.capability_generation,
        issuance_salt=first.capability_issuance_salt,
    )
    grant = issue_capability_grant(
        relay_issuance,
        capability_id=capability_id,
        capability_generation=first.capability_generation,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        permissions=("post", "fetch"),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    store.save_capability_grant(
        relay_name="relay",
        grant=grant,
        auth_private=auth_private,
        issuance_salt=first.capability_issuance_salt,
        relay_tls_spki_sha256=tls_pin,
    )

    second = enrich_descriptor_capabilities(store, first)
    assert second.capability_generation == 2
    assert second.capability_issuance_salt != first.capability_issuance_salt

    profile = create_delivery_profile(alice, relay_descriptors=[second])
    generation, salt = capability_material_params(store, "relay", operator_profile=profile)
    assert generation == 2
    assert salt == second.capability_issuance_salt

    first_id, _ = derive_capability_material(
        contact.master_secret,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=first.capability_generation,
        issuance_salt=first.capability_issuance_salt,
    )
    second_id, _ = derive_capability_material(
        contact.master_secret,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=second.capability_generation,
        issuance_salt=second.capability_issuance_salt,
    )
    assert first_id != second_id
