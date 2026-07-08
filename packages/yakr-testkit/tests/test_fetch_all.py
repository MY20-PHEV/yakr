from __future__ import annotations

import os
import secrets
from pathlib import Path

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.presence import PresencePayload, fresh_group_relay_urls
from yakr_core.store import FileLocalStore
from yakr_cli.fetch_cmds import fetch_all_contacts
from yakr_cli.network import fetch_mailbox_urls, _trust_graph_mailbox_urls
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_fresh_group_relay_urls_dedupes(tmp_path: Path) -> None:
    store = FileLocalStore(tmp_path / "alice")
    store.save_presence(
        PresencePayload.for_operator("charlie", "https://charlie:8090"),
        source_contact="charlie",
    )
    store.save_presence(
        PresencePayload.for_operator("dennis", "https://dennis:8090"),
        source_contact="dennis",
    )
    urls = fresh_group_relay_urls(store)
    assert urls == ["https://charlie:8090", "https://dennis:8090"]


def test_trust_graph_includes_presence_group_relays(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    wrap = secrets.token_bytes(32)
    contact.delivery_profile = create_delivery_profile(
        bob,
        relay_descriptors=[RelayDescriptor("bob", "both", "https://bob-relay:8090", wrap)],
    )
    store = FileLocalStore(tmp_path / "alice")
    store.save_contact(contact)
    store.save_presence(
        PresencePayload.for_operator("dennis", "https://dennis-group:8090"),
        source_contact="dennis",
    )
    urls = _trust_graph_mailbox_urls(store, contact)
    assert "https://dennis-group:8090" in urls
    assert "https://bob-relay:8090" in urls


def test_fetch_mailbox_urls_without_env_relay(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        charlie_contact = mesh.alice.store.get_contact("charlie")
        assert charlie_contact is not None
        previous = os.environ.pop("YAKR_RELAY_URL", None)
        try:
            urls = fetch_mailbox_urls(charlie_contact, None, store=mesh.alice.store)
        finally:
            if previous is not None:
                os.environ["YAKR_RELAY_URL"] = previous
        assert mesh.charlie_relay.relay_url.rstrip("/") in urls
    finally:
        mesh.stop()


def test_fetch_all_contacts(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.charlie.send("alice", "hello from charlie")
        mesh.bob.send("alice", "hello from bob")
        previous = os.environ.pop("YAKR_RELAY_URL", None)
        try:
            total, contacts = fetch_all_contacts(
                mesh.alice.store,
                mesh.alice.identity,
            )
        finally:
            if previous is not None:
                os.environ["YAKR_RELAY_URL"] = previous
        assert total == 2
        assert contacts == 2
    finally:
        mesh.stop()
