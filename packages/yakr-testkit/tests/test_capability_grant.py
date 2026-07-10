"""Relay capability grant tests."""

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
    verify_capability_grant,
    verify_capability_request,
)
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def capability_relay(tmp_path):
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
    yield url, relay_issuance, tls_pin
    server.should_exit = True
    thread.join(timeout=2)


def test_self_signed_capability_without_registration_fails(capability_relay) -> None:
    url, relay_issuance, tls_pin = capability_relay
    auth_private = ed25519.Ed25519PrivateKey.generate()
    forged = issue_capability_grant(
        auth_private,
        capability_id=secrets.token_bytes(16),
        capability_generation=1,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        permissions=("post",),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    payload = {
        "mailbox_tag": "dGVzdA",
        "expires_at": int(time.time() * 1000) + 60_000,
        "ciphertext": "Ym9keQ",
    }
    body = json.dumps(payload).encode("utf-8")
    headers = capability_request_headers(
        forged,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=body,
    )
    response = httpx.post(
        f"{url}/v1/blobs",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
        timeout=5.0,
    )
    assert response.status_code == 401


def test_registered_capability_allows_blob_post(capability_relay) -> None:
    url, relay_issuance, tls_pin = capability_relay
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
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
        permissions=("post",),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    verify_capability_grant(
        grant,
        relay_signing_public=relay_issuance.public_key().public_bytes_raw(),
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
    )
    register = httpx.post(
        f"{url}/v1/capabilities/register",
        json={"grant": grant.to_b64()},
        timeout=5.0,
    )
    assert register.status_code == 201

    encrypted = Session(alice, contact).encrypt_text("capability path")
    payload = encrypted.outer_blob.to_relay_json()
    body = json.dumps(payload).encode("utf-8")
    headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=body,
    )
    response = httpx.post(
        f"{url}/v1/blobs",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
        timeout=5.0,
    )
    assert response.status_code == 201


def test_capability_rotation_changes_capability_id() -> None:
    master = secrets.token_bytes(32)
    tls_pin = secrets.token_bytes(32)
    first_id, _ = derive_capability_material(
        master,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=1,
        issuance_salt=secrets.token_bytes(16),
    )
    second_id, _ = derive_capability_material(
        master,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        capability_generation=2,
        issuance_salt=secrets.token_bytes(16),
    )
    assert first_id != second_id
