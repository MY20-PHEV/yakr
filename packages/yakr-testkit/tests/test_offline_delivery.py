from __future__ import annotations

import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import OuterBlob
from yakr_core.session import Session
from yakr_relay.app import create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def relay_server(tmp_path: Path):
    store = BlobStore(tmp_path / "relay")
    app = create_app(store)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.should_exit = True
    thread.join(timeout=2)


def test_offline_delivery_roundtrip(relay_server: str) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))

    alice_session = Session(alice, alice_contact)
    encrypted = alice_session.encrypt_text("hello bob")

    response = httpx.post(
        f"{relay_server}/v1/blobs",
        json=encrypted.outer_blob.to_relay_json(),
        timeout=5.0,
    )
    assert response.status_code == 201

    bob_session = Session(bob, bob_contact)
    tags = bob_session.mailbox_deriver(outbound=False).candidate_epochs(bob_session.recv_direction)
    fetched = False
    for tag in tags:
        fetch = httpx.get(f"{relay_server}/v1/blobs/{tag.tag_b64}", timeout=5.0)
        assert fetch.status_code == 200
        for item in fetch.json():
            inner = bob_session.decrypt_outer(OuterBlob.from_relay_json(item))
            assert inner.body == "hello bob"
            fetched = True
    assert fetched
