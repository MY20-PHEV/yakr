"""Operator identity separation on capability wire paths."""

from __future__ import annotations

import json
import secrets
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.capability_client import issue_capability_from_relay
from yakr_core.capability_grant import capability_request_headers, issue_capability_grant
from yakr_core.delivery_profile import RelayDescriptor
from yakr_core.identity import Contact, Identity, b64encode, export_public_bundle
from yakr_core.store import FileLocalStore


def test_capability_issue_body_excludes_owner_contact_id(tmp_path, monkeypatch) -> None:
    alice = Identity.generate("alice")
    operator = Identity.generate("alice-ops")
    store = FileLocalStore(tmp_path)
    store.save_identity(alice)
    contact = Contact.establish(alice, "alice-ops", export_public_bundle(operator))
    store.save_contact(contact)

    descriptor = RelayDescriptor(
        name="alice-ops",
        role="both",
        url="https://relay.example:8090",
        wrap_secret=secrets.token_bytes(32),
        tls_spki_sha256=secrets.token_bytes(32),
        capability_generation=1,
        capability_issuance_salt=secrets.token_bytes(16),
    )
    from yakr_core.delivery_profile import create_delivery_profile

    profile = create_delivery_profile(alice, relay_descriptors=[descriptor])
    store.save_local_profile(profile)

    captured: dict[str, object] = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["content"] = kwargs.get("content", b"")
        response = MagicMock()
        response.status_code = 201
        response.json.return_value = {
            "grant": issue_capability_grant(
                ed25519.Ed25519PrivateKey.generate(),
                capability_id=secrets.token_bytes(16),
                capability_generation=1,
                relay_name="alice-ops",
                relay_tls_spki_sha256=descriptor.tls_spki_sha256,
                permissions=("post", "fetch"),
                auth_public=ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            ).to_b64()
        }
        return response

    monkeypatch.setattr("yakr_core.capability_client.yakr_post", fake_post)
    monkeypatch.setattr(
        "yakr_core.capability_client._bootstrap_ticket",
        lambda *args, **kwargs: "ticket-only-for-bootstrap",
    )
    monkeypatch.setattr(
        "yakr_core.capability_client._relay_tls_pin",
        lambda *args, **kwargs: descriptor.tls_spki_sha256,
    )
    monkeypatch.setattr(
        "yakr_core.capability_client.relay_supports_capabilities",
        lambda *args, **kwargs: True,
    )

    issue_capability_from_relay(
        descriptor.url,
        descriptor.name,
        identity=alice,
        contact=contact,
        store=store,
        operator_profile=profile,
    )

    body = json.loads(bytes(captured["content"]).decode("utf-8"))
    assert "contact_id" not in body
    assert b64encode(alice.signing_public_bytes) not in body.values()
    assert "auth_public" in body
    assert "capability_id" in body


def test_capability_request_headers_exclude_contact_id() -> None:
    relay_issuance = ed25519.Ed25519PrivateKey.generate()
    tls_pin = secrets.token_bytes(32)
    auth_private = ed25519.Ed25519PrivateKey.generate()
    grant = issue_capability_grant(
        relay_issuance,
        capability_id=secrets.token_bytes(16),
        capability_generation=1,
        relay_name="relay",
        relay_tls_spki_sha256=tls_pin,
        permissions=("post",),
        auth_public=auth_private.public_key().public_bytes_raw(),
    )
    headers = capability_request_headers(
        grant,
        auth_private,
        method="POST",
        path="/v1/blobs",
        body=b"{}",
    )
    joined = json.dumps(headers)
    assert "contact_id" not in joined
    assert "issuer_signing_public" not in joined
