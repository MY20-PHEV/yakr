"""POST /v1/fetch with capability authorization."""

from __future__ import annotations

import json
import secrets
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.capability_grant import (
    capability_request_headers,
    derive_capability_material,
    issue_capability_grant,
)
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore, _b64encode


@pytest.fixture
def capability_fetch_relay(tmp_path):
    relay_issuance = ed25519.Ed25519PrivateKey.generate()
    relay_public = relay_issuance.public_key().public_bytes_raw()
    tls_pin = secrets.token_bytes(32)
    store = BlobStore(tmp_path / "relay")
    runtime = RelayRuntime(
        role="mailbox",
        wrap_secret=None,
        name="relay",
        require_capabilities=True,
        relay_issuance_public=relay_public,
        relay_issuance_private=relay_issuance.private_bytes_raw(),
        relay_tls_spki_sha256=tls_pin,
    )
    app = create_app(store, runtime)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    yield url, relay_issuance, tls_pin, store
    server.should_exit = True
    thread.join(timeout=2)


def _register_grant(url: str, relay_issuance, tls_pin, alice, contact) -> tuple:
    issuance_salt = secrets.token_bytes(16)
    capability_id, auth_private = derive_capability_material(
        contact.master_secret,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=1,
        issuance_salt=issuance_salt,
    )
    grant = issue_capability_grant(
        relay_issuance,
        capability_id=capability_id,
        capability_generation=1,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        permissions=("post", "fetch"),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    register = httpx.post(
        f"{url}/v1/capabilities/register",
        json={"grant": grant.to_b64()},
        timeout=5.0,
    )
    assert register.status_code == 201
    return grant, auth_private


def test_post_fetch_with_capability(capability_fetch_relay) -> None:
    url, relay_issuance, tls_pin, _store = capability_fetch_relay
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    grant, auth_private = _register_grant(url, relay_issuance, tls_pin, alice, contact)

    encrypted = Session(alice, contact).encrypt_text("fetch via POST")
    store_payload = encrypted.outer_blob.to_relay_json()
    store_body = json.dumps(store_payload).encode("utf-8")
    store_headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=store_body,
    )
    stored = httpx.post(
        f"{url}/v1/blobs",
        content=store_body,
        headers={**store_headers, "Content-Type": "application/json"},
        timeout=5.0,
    )
    assert stored.status_code == 201

    tag_b64 = store_payload["mailbox_tag"]
    fetch_body = json.dumps({"mailbox_tags": [tag_b64]}).encode("utf-8")
    fetch_headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/fetch",
        body=fetch_body,
    )
    fetched = httpx.post(
        f"{url}/v1/fetch",
        content=fetch_body,
        headers={**fetch_headers, "Content-Type": "application/json"},
        timeout=5.0,
    )
    assert fetched.status_code == 200
    blobs = fetched.json()
    assert len(blobs) == 1
    assert blobs[0]["ciphertext"] == store_payload["ciphertext"]


def test_post_fetch_without_capability_rejected(capability_fetch_relay) -> None:
    url, relay_issuance, tls_pin, store = capability_fetch_relay
    tag = secrets.token_bytes(32)
    store.store(tag, int(time.time() * 1000) + 60_000, b"secret")
    tag_b64 = _b64encode(tag)
    fetch_body = json.dumps({"mailbox_tags": [tag_b64]}).encode("utf-8")
    response = httpx.post(
        f"{url}/v1/fetch",
        content=fetch_body,
        headers={"Content-Type": "application/json"},
        timeout=5.0,
    )
    assert response.status_code == 401


def test_legacy_get_fetch_still_works_without_capability(capability_fetch_relay) -> None:
    """GET /v1/blobs/{tag} remains open for v1 compatibility when not in URL-log-safe mode."""
    url, _relay_issuance, _tls_pin, store = capability_fetch_relay
    tag = secrets.token_bytes(32)
    store.store(tag, int(time.time() * 1000) + 60_000, b"legacy")
    tag_b64 = _b64encode(tag)
    response = httpx.get(f"{url}/v1/blobs/{tag_b64}", timeout=5.0)
    assert response.status_code == 200
    assert len(response.json()) == 1
