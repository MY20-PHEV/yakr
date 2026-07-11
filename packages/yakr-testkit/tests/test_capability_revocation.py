"""Capability revocation and overlap window tests."""

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
from yakr_core.identity import Contact, Identity, b64encode, export_public_bundle
from yakr_core.session import Session
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.capability_store import CapabilityGrantStore
from yakr_relay.store import BlobStore


@pytest.fixture
def capability_relay(tmp_path):
    relay_issuance = ed25519.Ed25519PrivateKey.generate()
    relay_public = relay_issuance.public_key().public_bytes_raw()
    tls_pin = secrets.token_bytes(32)
    store = BlobStore(tmp_path / "relay")
    capability_store = CapabilityGrantStore(
        store.root / "capabilities",
        overlap_window_ms=60_000,
    )
    runtime = RelayRuntime(
        role="mailbox",
        wrap_secret=None,
        name="relay",
        require_capabilities=True,
        relay_issuance_public=relay_public,
        relay_tls_spki_sha256=tls_pin,
    )
    app = create_app(store, runtime, capability_store=capability_store)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    yield url, relay_issuance, tls_pin, capability_store
    server.should_exit = True
    thread.join(timeout=2)


def _blob_post(url: str, grant, auth_private, *, alice: Identity, contact: Contact) -> httpx.Response:
    encrypted = Session(alice, contact).encrypt_text("revocation test")
    payload = encrypted.outer_blob.to_relay_json()
    body = json.dumps(payload).encode("utf-8")
    headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=body,
    )
    return httpx.post(
        f"{url}/v1/blobs",
        content=body,
        headers={**headers, "Content-Type": "application/json"},
        timeout=5.0,
    )


def _register_grant(url: str, grant) -> None:
    response = httpx.post(
        f"{url}/v1/capabilities/register",
        json={"grant": grant.to_b64()},
        timeout=5.0,
    )
    assert response.status_code == 201


def test_superseded_capability_works_during_overlap(capability_relay) -> None:
    url, relay_issuance, tls_pin, capability_store = capability_relay
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
    _register_grant(url, grant)

    now_ms = int(time.time() * 1000)
    capability_store.revoke_with_overlap(capability_id, now_ms=now_ms, overlap_window_ms=60_000)
    assert capability_store.is_registered(grant, now_ms=now_ms)
    assert _blob_post(url, grant, auth_private, alice=alice, contact=contact).status_code == 201


def test_superseded_capability_rejected_after_overlap(capability_relay) -> None:
    url, relay_issuance, tls_pin, capability_store = capability_relay
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
    _register_grant(url, grant)

    now_ms = int(time.time() * 1000)
    capability_store.revoke_with_overlap(capability_id, now_ms=now_ms, overlap_window_ms=1_000)
    time.sleep(1.1)
    assert not capability_store.is_registered(grant, now_ms=int(time.time() * 1000))
    assert _blob_post(url, grant, auth_private, alice=alice, contact=contact).status_code == 401


def test_capability_nonce_replay_rejected(capability_relay) -> None:
    url, relay_issuance, tls_pin, capability_store = capability_relay
    _ = capability_store
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
    _register_grant(url, grant)

    encrypted = Session(alice, contact).encrypt_text("nonce replay")
    payload = encrypted.outer_blob.to_relay_json()
    body = json.dumps(payload).encode("utf-8")
    headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=body,
    )
    request_headers = {**headers, "Content-Type": "application/json"}
    first = httpx.post(f"{url}/v1/blobs", content=body, headers=request_headers, timeout=5.0)
    second = httpx.post(f"{url}/v1/blobs", content=body, headers=request_headers, timeout=5.0)
    assert first.status_code == 201
    assert second.status_code == 401
