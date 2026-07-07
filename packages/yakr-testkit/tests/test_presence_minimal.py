from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.presence import (
    PresencePayload,
    apply_presence_message,
    is_presence_fresh,
    resolve_operator_url,
)
from yakr_core.message import InnerMessage
from yakr_core.store import FileLocalStore
from yakr_cli.network import delivery_mailbox_urls
from yakr_cli.presence_cmds import broadcast_presence
from yakr_testkit.mesh_setup import build_charlie_mesh


def test_presence_payload_roundtrip() -> None:
    payload = PresencePayload.for_operator("charlie", "http://10.0.0.5:8090")
    restored = PresencePayload.from_b64(payload.to_b64())
    assert restored == payload
    assert is_presence_fresh(restored)


def test_resolve_operator_url_prefers_fresh_presence(tmp_path: Path) -> None:
    store = FileLocalStore(tmp_path / "alice")
    payload = PresencePayload.for_operator("charlie", "http://fresh:8090")
    store.save_presence(payload, source_contact="charlie")
    assert resolve_operator_url(store, "charlie", "http://stale:8090") == "http://fresh:8090"
    assert resolve_operator_url(None, "charlie", "http://stale:8090") == "http://stale:8090"


def test_delivery_mailbox_urls_uses_presence_over_stale_profile(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    charlie = Identity.generate("charlie")
    contact = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    wrap = secrets.token_bytes(32)
    contact.delivery_profile = create_delivery_profile(
        charlie,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", "http://127.0.0.1:1", wrap),
        ],
    )
    store = FileLocalStore(tmp_path / "alice")
    store.save_presence(
        PresencePayload.for_operator("charlie", "http://live:8090"),
        source_contact="charlie",
    )
    urls = delivery_mailbox_urls(contact, None, store=store)
    assert urls[0] == "http://live:8090"


def test_apply_presence_rejects_wrong_operator(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    charlie = Identity.generate("charlie")
    contact = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    payload = PresencePayload.for_operator("dennis", "http://dennis:8090")
    inner = InnerMessage.presence(
        conversation_id=contact.conversation_id,
        sender_device_id=charlie.device_id,
        seq=1,
        presence_b64=payload.to_b64(),
    )
    store = FileLocalStore(tmp_path / "alice")
    with pytest.raises(Exception) as exc:
        apply_presence_message(store, contact, inner)
    assert "does not match" in str(exc.value)


def test_charlie_pushes_presence_to_alice_via_dennis(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        mesh.charlie.store.save_local_profile(
            create_delivery_profile(
                mesh.charlie.identity,
                relay_descriptors=[
                    RelayDescriptor(
                        "charlie",
                        "both",
                        mesh.charlie_relay.relay_url,
                        mesh.charlie_relay.wrap_secret,
                    ),
                    RelayDescriptor(
                        "dennis",
                        "both",
                        mesh.dennis_relay.relay_url,
                        mesh.dennis_relay.wrap_secret,
                    ),
                ],
            )
        )
        mesh.charlie_relay.stop()
        new_url = mesh.dennis_relay.relay_url
        payload = PresencePayload.for_operator("charlie", new_url)
        broadcast_presence(mesh.charlie.store, mesh.charlie.identity, [payload], contact_name="alice")

        mesh.alice.fetch("charlie")
        cached = mesh.alice.store.load_presence("charlie")
        assert cached is not None
        assert cached.reachable_url == new_url.rstrip("/")
        assert is_presence_fresh(cached)

        mesh.alice.store.save_local_profile(
            create_delivery_profile(
                mesh.alice.identity,
                relay_descriptors=[
                    RelayDescriptor(
                        "charlie",
                        "both",
                        "http://127.0.0.1:1",
                        mesh.charlie_relay.wrap_secret,
                    ),
                    RelayDescriptor(
                        "dennis",
                        "both",
                        mesh.dennis_relay.relay_url,
                        mesh.dennis_relay.wrap_secret,
                    ),
                ],
            )
        )
        charlie_contact = mesh.alice.store.get_contact("charlie")
        assert charlie_contact is not None
        urls = delivery_mailbox_urls(charlie_contact, None, store=mesh.alice.store)
        assert urls[0] == new_url.rstrip("/")
    finally:
        mesh.stop()


def test_presence_push_updates_alice_cache(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        payload = PresencePayload.for_operator("charlie", mesh.dennis_relay.relay_url)
        broadcast_presence(
            mesh.charlie.store,
            mesh.charlie.identity,
            [payload],
            contact_name="alice",
        )
        mesh.alice.fetch("charlie")
        cached = mesh.alice.store.load_presence("charlie")
        assert cached is not None
        assert cached.reachable_url == mesh.dennis_relay.relay_url.rstrip("/")
    finally:
        mesh.stop()
