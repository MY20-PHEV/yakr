from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.profile_ack import apply_peer_profile_ack
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted, delivery_mailbox_urls
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def dual_mailbox_relays(tmp_path: Path):
    secrets_map = {
        "primary": secrets.token_bytes(32),
        "secondary": secrets.token_bytes(32),
    }
    servers: list[uvicorn.Server] = []
    urls: dict[str, str] = {}

    for name in ("primary", "secondary"):
        store = BlobStore(tmp_path / name)
        app = create_app(
            store,
            RelayRuntime(role="both", wrap_secret=secrets_map[name], name=name),
        )
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        while not server.started:
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        urls[name] = f"http://127.0.0.1:{port}"
        servers.append(server)

    yield urls, secrets_map

    for server in servers:
        server.should_exit = True


def test_delivery_mailbox_urls_prefers_recipient_then_sender(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    contact.delivery_profile = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("bob-relay", "both", "http://bob-relay", secrets.token_bytes(32)),
        ],
    )
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_profile = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("alice-a", "both", "http://alice-a", secrets.token_bytes(32)),
            RelayDescriptor("alice-b", "both", "http://alice-b", secrets.token_bytes(32)),
        ],
    )
    alice_store.save_local_profile(alice_profile)
    apply_peer_profile_ack(contact, alice_profile)
    alice_store.save_contact(contact)

    urls = delivery_mailbox_urls(contact, None, store=alice_store)
    assert urls == ["http://bob-relay", "http://alice-a", "http://alice-b"]


def test_deliver_failover_to_secondary_relay(dual_mailbox_relays, tmp_path: Path) -> None:
    urls, secrets_map = dual_mailbox_relays
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_profile = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("primary", "both", urls["primary"], secrets_map["primary"]),
            RelayDescriptor("secondary", "both", urls["secondary"], secrets_map["secondary"]),
        ],
    )
    alice_store.save_local_profile(alice_profile)
    apply_peer_profile_ack(contact, alice_profile)
    alice_store.save_contact(contact)

    # Primary relay offline — delivery should land on secondary.
    dead_primary = "http://127.0.0.1:1"
    alice_profile_dead = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("primary", "both", dead_primary, secrets_map["primary"]),
            RelayDescriptor("secondary", "both", urls["secondary"], secrets_map["secondary"]),
        ],
        version=2,
    )
    alice_store.save_local_profile(alice_profile_dead)
    apply_peer_profile_ack(contact, alice_profile_dead)
    alice_store.save_contact(contact)

    encrypted = Session(alice, contact).encrypt_text("failover please")
    mode = deliver_encrypted(encrypted, contact=contact, identity=alice, store=alice_store)
    assert mode == "relay-failover:secondary"

    primary = httpx.get(
        f"{urls['primary']}/v1/blobs/{encrypted.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    secondary = httpx.get(
        f"{urls['secondary']}/v1/blobs/{encrypted.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    assert primary.status_code == 200 and primary.json() == []
    assert secondary.status_code == 200 and len(secondary.json()) == 1


def test_deliver_uses_primary_when_healthy(dual_mailbox_relays, tmp_path: Path) -> None:
    urls, secrets_map = dual_mailbox_relays
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_profile = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("primary", "both", urls["primary"], secrets_map["primary"]),
            RelayDescriptor("secondary", "both", urls["secondary"], secrets_map["secondary"]),
        ],
    )
    alice_store.save_local_profile(alice_profile)
    apply_peer_profile_ack(contact, alice_profile)
    alice_store.save_contact(contact)

    encrypted = Session(alice, contact).encrypt_text("primary path")
    mode = deliver_encrypted(encrypted, contact=contact, identity=alice, store=alice_store)
    assert mode == "relay:primary"
