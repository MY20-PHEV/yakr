from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import OuterBlob, message_id
from yakr_core.onion import build_onion_packet, decode_entry_packet, decode_mailbox_packet
from yakr_core.relay import RelayNode, save_relay_network
from yakr_core.session import Session
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def two_hop_relays(tmp_path: Path):
    entry_secret = secrets.token_bytes(32)
    mailbox_secret = secrets.token_bytes(32)

    entry_store = BlobStore(tmp_path / "entry")
    mailbox_store = BlobStore(tmp_path / "mailbox")

    entry_app = create_app(
        entry_store,
        RelayRuntime(role="both", wrap_secret=entry_secret, name="dennis"),
    )
    mailbox_app = create_app(
        mailbox_store,
        RelayRuntime(role="both", wrap_secret=mailbox_secret, name="charlie"),
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

    start(entry_app, "dennis")
    start(mailbox_app, "charlie")

    relays_file = tmp_path / "relays.json"
    save_relay_network(
        relays_file,
        {
            "dennis": RelayNode("dennis", "entry", urls["dennis"], entry_secret),
            "charlie": RelayNode("charlie", "mailbox", urls["charlie"], mailbox_secret),
        },
    )

    yield urls, relays_file, entry_secret, mailbox_secret

    for server in servers:
        server.should_exit = True


def test_onion_packet_roundtrip(two_hop_relays) -> None:
    urls, relays_file, entry_secret, mailbox_secret = two_hop_relays
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    encrypted = Session(alice, contact).encrypt_text("cbor packet")

    packet = build_onion_packet(
        entry_wrap_secret=entry_secret,
        mailbox_wrap_secret=mailbox_secret,
        entry_relay_url=urls["dennis"],
        mailbox_relay_url=urls["charlie"],
        outer=encrypted.outer_blob,
    )

    next_url, inner = decode_entry_packet(packet, entry_secret)
    assert next_url.endswith("/v1/ingest")
    outer = decode_mailbox_packet(inner, mailbox_secret)
    assert outer.ciphertext == encrypted.outer_blob.ciphertext


def test_two_hop_delivery_and_receipt(two_hop_relays) -> None:
    urls, relays_file, entry_secret, mailbox_secret = two_hop_relays
    os.environ["YAKR_RELAYS_FILE"] = str(relays_file)

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))

    alice_session = Session(alice, alice_contact)
    encrypted = alice_session.encrypt_text("two hop hello")
    packet = build_onion_packet(
        entry_wrap_secret=entry_secret,
        mailbox_wrap_secret=mailbox_secret,
        entry_relay_url=urls["dennis"],
        mailbox_relay_url=urls["charlie"],
        outer=encrypted.outer_blob,
    )

    import base64

    packet_b64 = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
    forward = httpx.post(f"{urls['dennis']}/v1/relay", json={"packet": packet_b64}, timeout=5.0)
    assert forward.status_code == 202

    bob_session = Session(bob, bob_contact)
    tags = bob_session.mailbox_deriver(outbound=False).candidate_epochs(bob_session.recv_direction)
    delivered_id = None
    for tag in tags:
        blobs = httpx.get(f"{urls['charlie']}/v1/blobs/{tag.tag_b64}", timeout=5.0).json()
        for item in blobs:
            inner = bob_session.decrypt_outer(OuterBlob.from_relay_json(item))
            assert inner.body == "two hop hello"
            delivered_id = message_id(OuterBlob.from_relay_json(item).ciphertext)

    assert delivered_id is not None

    receipt = bob_session.encrypt_receipt(delivered_id)
    reverse_packet = build_onion_packet(
        entry_wrap_secret=mailbox_secret,
        mailbox_wrap_secret=entry_secret,
        entry_relay_url=urls["charlie"],
        mailbox_relay_url=urls["dennis"],
        outer=receipt.outer_blob,
    )
    reverse_b64 = base64.urlsafe_b64encode(reverse_packet).decode("ascii").rstrip("=")
    reverse = httpx.post(f"{urls['charlie']}/v1/relay", json={"packet": reverse_b64}, timeout=5.0)
    assert reverse.status_code == 202

    alice_session = Session(alice, alice_contact)
    recv_tags = alice_session.mailbox_deriver(outbound=False).candidate_epochs(
        alice_session.recv_direction
    )
    got_receipt = False
    for tag in recv_tags:
        blobs = httpx.get(f"{urls['dennis']}/v1/blobs/{tag.tag_b64}", timeout=5.0).json()
        for item in blobs:
            inner = alice_session.decrypt_outer(OuterBlob.from_relay_json(item))
            if inner.type == "receipt":
                assert inner.message_id == delivered_id
                got_receipt = True
    assert got_receipt
