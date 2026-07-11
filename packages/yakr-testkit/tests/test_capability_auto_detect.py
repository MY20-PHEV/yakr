"""Auto-detect relay capability mode from /healthz."""

from __future__ import annotations

import secrets
import threading
import time

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_cli.network import fetch_relay_blobs, send_encrypted
from yakr_core.capability_client import (
    _capability_probe_cache,
    probe_relay_issuance_public,
    relay_supports_capabilities,
)
from yakr_core.capability_grant import derive_capability_material, issue_capability_grant
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture(autouse=True)
def clear_capability_probe_cache() -> None:
    _capability_probe_cache.clear()
    yield
    _capability_probe_cache.clear()


@pytest.fixture
def capability_auto_relay(tmp_path):
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
    yield url, relay_issuance, tls_pin
    server.should_exit = True
    thread.join(timeout=2)


def test_probe_relay_issuance_public_from_healthz(capability_auto_relay, monkeypatch) -> None:
    url, relay_issuance, _tls_pin = capability_auto_relay
    monkeypatch.delenv("YAKR_USE_CAPABILITIES", raising=False)
    monkeypatch.delenv("YAKR_DISABLE_CAPABILITIES", raising=False)
    public = probe_relay_issuance_public(url)
    assert public == relay_issuance.public_key().public_bytes_raw()
    assert relay_supports_capabilities(url) is True


def test_network_uses_capabilities_without_env_flag(
    capability_auto_relay,
    tmp_path,
    monkeypatch,
) -> None:
    url, relay_issuance, tls_pin = capability_auto_relay
    monkeypatch.delenv("YAKR_USE_CAPABILITIES", raising=False)
    monkeypatch.delenv("YAKR_DISABLE_CAPABILITIES", raising=False)
    monkeypatch.setenv("YAKR_TLS_INSECURE", "1")

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    store = FileLocalStore(tmp_path / "alice")
    store.save_identity(alice)
    store.save_contact(contact)

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
    import httpx

    assert httpx.post(
        f"{url}/v1/capabilities/register",
        json={"grant": grant.to_b64()},
        timeout=5.0,
    ).status_code == 201
    store.save_capability_grant(
        relay_name="relay",
        grant=grant,
        auth_private=auth_private,
        issuance_salt=issuance_salt,
        relay_tls_spki_sha256=tls_pin,
    )

    encrypted = Session(alice, contact).encrypt_text("auto capability path")
    send_encrypted(
        encrypted,
        relay_url=url,
        identity=alice,
        contact=contact,
        store=store,
    )

    blobs = fetch_relay_blobs(
        encrypted.mailbox_tag.tag_b64,
        [url],
        store=store,
        contact=contact,
        identity=alice,
    )
    assert len(blobs) == 1


def test_disable_capabilities_env_opt_out(capability_auto_relay, monkeypatch) -> None:
    url, _relay_issuance, _tls_pin = capability_auto_relay
    monkeypatch.setenv("YAKR_DISABLE_CAPABILITIES", "1")
    assert relay_supports_capabilities(url) is False
