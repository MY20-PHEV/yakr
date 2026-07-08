"""Sender fallback gated on peer-acknowledged delivery profile relays."""

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
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore
from yakr_cli.network import delivery_mailbox_urls


@pytest.fixture
def relay_pair(tmp_path: Path):
    charlie_secret = secrets.token_bytes(32)
    eve_secret = secrets.token_bytes(32)
    charlie_store = BlobStore(tmp_path / "charlie")
    eve_store = BlobStore(tmp_path / "eve")
    charlie_app = create_app(
        charlie_store,
        RelayRuntime(role="both", wrap_secret=charlie_secret, name="charlie"),
    )
    eve_app = create_app(
        eve_store,
        RelayRuntime(role="both", wrap_secret=eve_secret, name="eve"),
    )
    servers: list[uvicorn.Server] = []
    urls: dict[str, str] = {}

    def start(app, key: str) -> None:
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        urls[key] = f"http://127.0.0.1:{port}"
        servers.append(server)

    start(charlie_app, "charlie")
    start(eve_app, "eve")
    yield urls, charlie_secret, eve_secret
    for server in servers:
        server.should_exit = True


def test_sender_fallback_excludes_unacked_relay(relay_pair, tmp_path: Path) -> None:
    urls, charlie_secret, eve_secret = relay_pair
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    v1 = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", urls["charlie"], charlie_secret),
        ],
        version=1,
    )
    v2 = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", urls["charlie"], charlie_secret),
            RelayDescriptor("eve", "both", urls["eve"], eve_secret),
        ],
        version=2,
    )
    alice_store.save_local_profile(v2)

    bob_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact.delivery_profile = create_delivery_profile(bob, relay_descriptors=[])
    apply_peer_profile_ack(bob_contact, v1)
    alice_store.save_contact(bob_contact)

    send_urls = delivery_mailbox_urls(bob_contact, None, store=alice_store)
    assert urls["charlie"] in send_urls
    assert urls["eve"] not in send_urls


def test_sender_fallback_includes_relay_after_profile_ack(relay_pair, tmp_path: Path) -> None:
    urls, charlie_secret, eve_secret = relay_pair
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    v2 = create_delivery_profile(
        alice,
        relay_descriptors=[
            RelayDescriptor("charlie", "both", urls["charlie"], charlie_secret),
            RelayDescriptor("eve", "both", urls["eve"], eve_secret),
        ],
        version=2,
    )
    alice_store.save_local_profile(v2)

    bob_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact.delivery_profile = create_delivery_profile(bob, relay_descriptors=[])
    apply_peer_profile_ack(bob_contact, v2)
    alice_store.save_contact(bob_contact)

    send_urls = delivery_mailbox_urls(bob_contact, None, store=alice_store)
    assert urls["charlie"] in send_urls
    assert urls["eve"] in send_urls
