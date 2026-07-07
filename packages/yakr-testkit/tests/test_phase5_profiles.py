from __future__ import annotations

import logging
import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.delivery_profile import (
    DeliveryProfile,
    RelayDescriptor,
    create_delivery_profile,
    profile_is_stale,
    verify_delivery_profile,
)
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.relay import RelayNode, save_relay_network
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.direct_server import DirectServerState, create_direct_app
from yakr_cli.network import (
    deliver_encrypted,
    fetch_remote_profile,
    refresh_contact_profile,
    try_direct_delivery,
)
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def profile_relays(tmp_path: Path):
    mailbox_a_secret = secrets.token_bytes(32)
    mailbox_b_secret = secrets.token_bytes(32)
    entry_secret = secrets.token_bytes(32)

    stores = {
        "mailbox_a": BlobStore(tmp_path / "mailbox_a"),
        "mailbox_b": BlobStore(tmp_path / "mailbox_b"),
        "entry": BlobStore(tmp_path / "entry"),
    }
    servers: list[uvicorn.Server] = []
    urls: dict[str, str] = {}

    def start(name: str, role: str, secret: bytes | None) -> None:
        app = create_app(stores[name], RelayRuntime(role=role, wrap_secret=secret, name=name))
        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        urls[name] = f"http://127.0.0.1:{port}"
        servers.append(server)

    start("mailbox_a", "mailbox", mailbox_a_secret)
    start("mailbox_b", "mailbox", mailbox_b_secret)
    start("entry", "both", entry_secret)

    relays_file = tmp_path / "relays.json"
    save_relay_network(
        relays_file,
        {
            "dennis": RelayNode("dennis", "entry", urls["entry"], entry_secret),
            "mailbox_a": RelayNode("mailbox_a", "mailbox", urls["mailbox_a"], mailbox_a_secret),
            "mailbox_b": RelayNode("mailbox_b", "mailbox", urls["mailbox_b"], mailbox_b_secret),
        },
    )

    yield urls, relays_file, mailbox_a_secret, mailbox_b_secret, entry_secret

    for server in servers:
        server.should_exit = True


@pytest.fixture
def direct_server(tmp_path: Path):
    state = DirectServerState()
    app = create_direct_app(state)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    yield state, base
    server.should_exit = True
    thread.join(timeout=2)


def test_delivery_profile_sign_verify() -> None:
    bob = Identity.generate("bob")
    profile = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "http://127.0.0.1:8080", secrets.token_bytes(32))
        ],
        direct_hints=["http://127.0.0.1:9000"],
    )
    verify_delivery_profile(profile, bob.signing_public_bytes)
    roundtrip = DeliveryProfile.from_bytes(profile.to_bytes())
    assert roundtrip.version == profile.version


def test_profile_update_changes_mailbox_without_relays_edit(profile_relays, tmp_path) -> None:
    urls, relays_file, mailbox_a_secret, mailbox_b_secret, entry_secret = profile_relays
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))

    initial = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("dennis", "entry", urls["entry"], entry_secret),
            RelayDescriptor("mailbox_a", "mailbox", urls["mailbox_a"], mailbox_a_secret),
        ],
        version=1,
    )
    contact.delivery_profile = initial

    encrypted = Session(alice, contact).encrypt_text("via mailbox a")
    deliver_encrypted(encrypted, contact=contact, route="dennis,mailbox_a")

    response = httpx.get(
        f"{urls['mailbox_a']}/v1/blobs/{encrypted.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    assert response.status_code == 200
    assert len(response.json()) == 1

    updated = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("dennis", "entry", urls["entry"], entry_secret),
            RelayDescriptor("mailbox_b", "mailbox", urls["mailbox_b"], mailbox_b_secret),
        ],
        version=2,
    )
    contact.delivery_profile = updated

    encrypted_b = Session(alice, contact).encrypt_text("via mailbox b")
    store = FileLocalStore(tmp_path / "alice")
    mode = deliver_encrypted(encrypted_b, contact=contact, route="auto", store=store)
    assert "mailbox_b" in mode or mode.startswith("two-hop")

    response_b = httpx.get(
        f"{urls['mailbox_b']}/v1/blobs/{encrypted_b.mailbox_tag.tag_b64}",
        timeout=5.0,
    )
    assert response_b.status_code == 200
    assert len(response_b.json()) == 1


def test_stale_profile_refresh_via_direct_hint(direct_server, tmp_path, caplog) -> None:
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(tmp_path / "alice")

    stale = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "http://127.0.0.1:1", secrets.token_bytes(32))
        ],
        direct_hints=[direct_server[1]],
        ttl_ms=1,
    )
    time.sleep(0.01)
    assert profile_is_stale(stale)

    fresh = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "http://127.0.0.1:8080", secrets.token_bytes(32))
        ],
        direct_hints=[direct_server[1]],
        version=2,
    )
    direct_server[0].profile = fresh

    contact = Contact.establish(Identity.generate("alice"), "bob", export_public_bundle(bob))
    contact.delivery_profile = stale

    with caplog.at_level(logging.WARNING):
        refreshed = refresh_contact_profile(alice_store, contact)
    assert refreshed is True
    assert contact.delivery_profile is not None
    assert contact.delivery_profile.version == 2
    assert "stale" in caplog.text.lower()


def test_direct_p2p_bypasses_relay(direct_server) -> None:
    state, base = direct_server
    bob = Identity.generate("bob")
    alice = Identity.generate("alice")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    profile = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "http://127.0.0.1:1", secrets.token_bytes(32))
        ],
        direct_hints=[base],
    )
    state.profile = profile
    contact.delivery_profile = profile

    encrypted = Session(alice, contact).encrypt_text("direct hello")
    assert try_direct_delivery(encrypted, [base]) is True

    fetched = httpx.get(
        f"{base}/v1/direct/blobs/{encrypted.mailbox_tag.tag_b64}",
        timeout=2.0,
    )
    assert fetched.status_code == 200
    assert len(fetched.json()) == 1

    mode = deliver_encrypted(encrypted, contact=contact)
    assert mode == "direct"


def test_fetch_remote_profile(direct_server) -> None:
    state, base = direct_server
    bob = Identity.generate("bob")
    profile = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "http://127.0.0.1:8080", secrets.token_bytes(32))
        ],
    )
    state.profile = profile
    fetched = fetch_remote_profile([base], bob.signing_public_bytes)
    assert fetched is not None
    assert fetched.version == profile.version
