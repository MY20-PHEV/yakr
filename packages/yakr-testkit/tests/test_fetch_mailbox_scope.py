from __future__ import annotations

import secrets
from pathlib import Path

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.presence import PresencePayload
from yakr_core.store import FileLocalStore
from yakr_cli.network import (
    _contact_fetch_mailbox_urls,
    _trust_graph_mailbox_urls,
    fetch_mailbox_urls,
)


def test_contact_fetch_excludes_other_contacts_relays(tmp_path: Path) -> None:
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(bob, "alice", export_public_bundle(Identity.generate("alice")))
    alice_contact.delivery_profile = create_delivery_profile(
        Identity.generate("alice"),
        relay_descriptors=[
            RelayDescriptor("charlie", "both", "https://charlie:8090", secrets.token_bytes(32)),
        ],
    )
    geoff_contact = Contact.establish(bob, "geoff", export_public_bundle(Identity.generate("geoff")))
    geoff_contact.delivery_profile = create_delivery_profile(
        Identity.generate("geoff"),
        relay_descriptors=[
            RelayDescriptor("geoff", "both", "https://geoff:8091", secrets.token_bytes(32)),
        ],
    )

    store = FileLocalStore(tmp_path / "bob")
    store.save_contact(alice_contact)
    store.save_contact(geoff_contact)

    alice_urls = _contact_fetch_mailbox_urls(store, alice_contact)
    assert "https://charlie:8090" in alice_urls
    assert "https://geoff:8091" not in alice_urls

    wide_urls = _trust_graph_mailbox_urls(store, alice_contact)
    assert "https://geoff:8091" in wide_urls


def test_fetch_mailbox_urls_default_is_per_contact(tmp_path: Path) -> None:
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(bob, "alice", export_public_bundle(Identity.generate("alice")))
    alice_contact.delivery_profile = create_delivery_profile(
        Identity.generate("alice"),
        relay_descriptors=[
            RelayDescriptor("charlie", "both", "https://charlie:8090", secrets.token_bytes(32)),
        ],
    )
    geoff_contact = Contact.establish(bob, "geoff", export_public_bundle(Identity.generate("geoff")))
    geoff_contact.delivery_profile = create_delivery_profile(
        Identity.generate("geoff"),
        relay_descriptors=[
            RelayDescriptor("geoff", "both", "https://geoff:8091", secrets.token_bytes(32)),
        ],
    )
    store = FileLocalStore(tmp_path / "bob")
    store.save_contact(alice_contact)
    store.save_contact(geoff_contact)

    narrow = fetch_mailbox_urls(alice_contact, None, store=store)
    assert "https://charlie:8090" in narrow
    assert "https://geoff:8091" not in narrow

    wide = fetch_mailbox_urls(alice_contact, None, store=store, wide=True)
    assert "https://geoff:8091" in wide


def test_contact_fetch_includes_local_and_fresh_operator_presence(tmp_path: Path) -> None:
    bob = Identity.generate("bob")
    bob_profile = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("bob", "both", "https://bob-home:8090", secrets.token_bytes(32)),
        ],
    )
    alice_contact = Contact.establish(bob, "alice", export_public_bundle(Identity.generate("alice")))
    alice_contact.delivery_profile = create_delivery_profile(
        Identity.generate("alice"),
        relay_descriptors=[
            RelayDescriptor("charlie", "both", "https://charlie-profile:8090", secrets.token_bytes(32)),
        ],
    )
    store = FileLocalStore(tmp_path / "bob")
    store.save_local_profile(bob_profile)
    store.save_contact(alice_contact)
    store.save_presence(
        PresencePayload.for_operator("charlie", "https://charlie-presence:8090"),
        source_contact="charlie",
    )

    urls = _contact_fetch_mailbox_urls(store, alice_contact)
    assert "https://bob-home:8090" in urls
    assert "https://charlie-presence:8090" in urls
    assert "https://charlie-profile:8090" not in urls
