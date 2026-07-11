"""End-to-end capability rotation: supersede, overlap, and reject stale grants."""

from __future__ import annotations

import json
import secrets
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_cli.network import fetch_relay_blobs, send_encrypted
from yakr_core.capability_client import (
    enrich_descriptor_capabilities,
    issue_capability_from_relay,
)
from yakr_core.capability_grant import (
    capability_request_headers,
    derive_capability_material,
    issue_capability_grant,
)
from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.pairing import contact_id_for
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.capability_store import CapabilityGrantStore
from yakr_relay.store import BlobStore

RELAY_NAME = "ops"


@pytest.fixture
def capability_rotation_relay(tmp_path):
    relay_issuance = ed25519.Ed25519PrivateKey.generate()
    relay_public = relay_issuance.public_key().public_bytes_raw()
    tls_pin = secrets.token_bytes(32)
    store = BlobStore(tmp_path / "relay")
    capability_store = CapabilityGrantStore(
        store.root / "capabilities",
        overlap_window_ms=1_000,
    )
    runtime = RelayRuntime(
        role="mailbox",
        wrap_secret=None,
        name=RELAY_NAME,
        require_capabilities=True,
        relay_issuance_public=relay_public,
        relay_issuance_private=relay_issuance.private_bytes_raw(),
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


def _blob_post_with_session(
    url: str,
    session,
    *,
    alice: Identity,
    peer_contact: Contact,
) -> httpx.Response:
    encrypted = Session(alice, peer_contact).encrypt_text("rotation probe")
    payload = encrypted.outer_blob.to_relay_json()
    body = json.dumps(payload).encode("utf-8")
    headers = capability_request_headers(
        session.grant,
        session.auth_private,
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


def _setup_operator_store(
    tmp_path,
    url: str,
    tls_pin: bytes,
) -> tuple[FileLocalStore, Identity, Contact, Contact, RelayDescriptor]:
    ops = Identity.generate(RELAY_NAME)
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    store = FileLocalStore(tmp_path / "alice")
    store.save_identity(alice)

    bob_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    store.save_contact(bob_contact)

    ops_contact = Contact.establish(alice, RELAY_NAME, export_public_bundle(ops))
    ops_contact.contact_id = contact_id_for(ops_contact.signing_public, ops_contact.agreement_public)
    descriptor = RelayDescriptor(
        name=RELAY_NAME,
        role="both",
        url=url,
        wrap_secret=secrets.token_bytes(32),
        tls_spki_sha256=tls_pin,
    )
    ops_profile = create_delivery_profile(ops, relay_descriptors=[descriptor])
    ops_contact.delivery_profile = ops_profile
    store.save_contact(ops_contact)
    return store, alice, bob_contact, ops_contact, descriptor


def test_profile_rotation_supersedes_old_grant(
    capability_rotation_relay,
    tmp_path,
    monkeypatch,
) -> None:
    url, relay_issuance, tls_pin, _capability_store = capability_rotation_relay
    monkeypatch.setenv("YAKR_TLS_INSECURE", "1")
    store, alice, bob_contact, ops_contact, descriptor = _setup_operator_store(
        tmp_path,
        url,
        tls_pin,
    )
    relay_public = relay_issuance.public_key().public_bytes_raw()

    descriptor1 = enrich_descriptor_capabilities(store, descriptor)
    profile1 = create_delivery_profile(alice, relay_descriptors=[descriptor1])
    store.save_local_profile(profile1)
    session1 = issue_capability_from_relay(
        url,
        RELAY_NAME,
        identity=alice,
        contact=ops_contact,
        store=store,
        operator_profile=profile1,
        relay_issuance_public=relay_public,
    )

    first = Session(alice, bob_contact).encrypt_text("generation one")
    send_encrypted(
        first,
        relay_url=url,
        identity=alice,
        contact=bob_contact,
        store=store,
    )

    descriptor2 = enrich_descriptor_capabilities(store, descriptor1)
    profile2 = create_delivery_profile(alice, relay_descriptors=[descriptor2], version=2)
    store.save_local_profile(profile2)
    session2 = issue_capability_from_relay(
        url,
        RELAY_NAME,
        identity=alice,
        contact=ops_contact,
        store=store,
        operator_profile=profile2,
        relay_issuance_public=relay_public,
    )

    assert session1.grant.capability_id != session2.grant.capability_id
    assert session2.grant.capability_generation > session1.grant.capability_generation

    assert _blob_post_with_session(
        url,
        session1,
        alice=alice,
        peer_contact=bob_contact,
    ).status_code == 201

    second = Session(alice, bob_contact).encrypt_text("generation two")
    send_encrypted(
        second,
        relay_url=url,
        identity=alice,
        contact=bob_contact,
        store=store,
    )
    blobs = fetch_relay_blobs(
        second.mailbox_tag.tag_b64,
        [url],
        store=store,
        contact=bob_contact,
        identity=alice,
    )
    assert len(blobs) >= 1

    time.sleep(1.1)
    assert _blob_post_with_session(
        url,
        session1,
        alice=alice,
        peer_contact=bob_contact,
    ).status_code == 401
    assert _blob_post_with_session(
        url,
        session2,
        alice=alice,
        peer_contact=bob_contact,
    ).status_code == 201


def test_capabilities_ignore_ticket_env_on_blob_post(
    capability_rotation_relay,
    tmp_path,
    monkeypatch,
) -> None:
    url, relay_issuance, tls_pin, _capability_store = capability_rotation_relay
    monkeypatch.setenv("YAKR_TLS_INSECURE", "1")
    monkeypatch.setenv("YAKR_REQUIRE_TICKETS", "1")
    store, alice, bob_contact, ops_contact, descriptor = _setup_operator_store(
        tmp_path,
        url,
        tls_pin,
    )

    descriptor1 = enrich_descriptor_capabilities(store, descriptor)
    profile1 = create_delivery_profile(alice, relay_descriptors=[descriptor1])
    store.save_local_profile(profile1)
    issuance_salt = descriptor1.capability_issuance_salt
    capability_id, auth_private = derive_capability_material(
        ops_contact.master_secret,
        relay_name=RELAY_NAME,
        relay_tls_spki_sha256=tls_pin,
        capability_generation=descriptor1.capability_generation,
        issuance_salt=issuance_salt,
    )
    grant = issue_capability_grant(
        relay_issuance,
        capability_id=capability_id,
        capability_generation=descriptor1.capability_generation,
        relay_name=RELAY_NAME,
        relay_tls_spki_sha256=tls_pin,
        permissions=("post", "fetch"),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    assert httpx.post(
        f"{url}/v1/capabilities/register",
        json={"grant": grant.to_b64()},
        timeout=5.0,
    ).status_code == 201
    store.save_capability_grant(
        relay_name=RELAY_NAME,
        grant=grant,
        auth_private=auth_private,
        issuance_salt=issuance_salt,
        relay_tls_spki_sha256=tls_pin,
    )

    captured: dict[str, bytes] = {}

    def fake_post(target_url, **kwargs):
        captured["body"] = kwargs.get("content", b"")
        response = httpx.Response(201, json={"status": "stored"})
        return response

    monkeypatch.setattr("yakr_cli.network.yakr_post", fake_post)

    encrypted = Session(alice, bob_contact).encrypt_text("no ticket on wire")
    send_encrypted(
        encrypted,
        relay_url=url,
        identity=alice,
        contact=bob_contact,
        store=store,
    )

    payload = json.loads(captured["body"].decode("utf-8"))
    assert "ticket" not in payload
    assert "contact_id" not in payload
