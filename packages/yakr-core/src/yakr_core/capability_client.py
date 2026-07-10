"""Client-side relay capability grant lifecycle."""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.capability_grant import (
    CapabilityGrant,
    capability_request_headers,
    derive_capability_material,
    issue_capability_grant,
    verify_capability_grant,
)
from yakr_core.http_client import endpoint_base_url, resolve_tls_pin_for_url, yakr_post
from yakr_core.identity import Contact, Identity, b64decode, b64encode
from yakr_core.delivery_profile import mailbox_descriptors
from yakr_core.store import FileLocalStore

DEFAULT_CAPABILITY_PERMISSIONS = ("post", "fetch")


def capabilities_enabled() -> bool:
    return os.environ.get("YAKR_USE_CAPABILITIES", "").lower() in {"1", "true", "yes"}


@dataclass(frozen=True)
class CapabilitySession:
    grant: CapabilityGrant
    auth_private: ed25519.Ed25519PrivateKey


def _relay_tls_pin(
    relay_url: str,
    *,
    store: FileLocalStore | None,
    contact: Contact | None,
) -> bytes:
    pin = resolve_tls_pin_for_url(relay_url, store=store, contact=contact)
    if pin is None or len(pin) != 32:
        raise ValueError(f"no TLS SPKI pin for relay {relay_url}")
    return pin


def _bootstrap_ticket(
    identity: Identity,
    contact: Contact,
    relay_name: str,
    permissions: tuple[str, ...],
) -> str:
    if contact.contact_id is None:
        raise ValueError("contact missing contact_id for capability bootstrap")
    return issue_relay_ticket(
        identity,
        relay_name=relay_name,
        permissions=permissions,
        contact_id=contact.contact_id,
    ).to_b64()


def issue_capability_from_relay(
    relay_url: str,
    relay_name: str,
    *,
    identity: Identity,
    contact: Contact,
    store: FileLocalStore,
    permissions: tuple[str, ...] = DEFAULT_CAPABILITY_PERMISSIONS,
    relay_issuance_public: bytes | None = None,
) -> CapabilitySession:
    """Bootstrap a relay-signed grant via ticket, register it, and persist locally."""
    tls_pin = _relay_tls_pin(relay_url, store=store, contact=contact)
    stored = store.load_capability_grant(relay_name)
    generation = 1 if stored is None else stored["capability_generation"] + 1
    issuance_salt = secrets.token_bytes(16)
    capability_id, auth_private = derive_capability_material(
        contact.master_secret,
        relay_name=relay_name,
        relay_tls_spki_sha256=tls_pin,
        capability_generation=generation,
        issuance_salt=issuance_salt,
    )
    auth_public = auth_private.public_key().public_bytes_raw()
    ticket = _bootstrap_ticket(identity, contact, relay_name, ("store", "fetch"))

    issue_body = json.dumps(
        {
            "auth_public": b64encode(auth_public),
            "capability_id": b64encode(capability_id),
            "capability_generation": generation,
            "issuance_salt": b64encode(issuance_salt),
            "permissions": list(permissions),
            "ticket": ticket,
        }
    ).encode("utf-8")
    issue_response = yakr_post(
        f"{relay_url.rstrip('/')}/v1/capabilities/issue",
        store=store,
        contact=contact,
        identity=identity,
        content=issue_body,
        headers={"Content-Type": "application/json"},
        timeout=10.0,
    )
    if issue_response.status_code != 201:
        raise RuntimeError(
            f"capability issue failed: {issue_response.status_code} {issue_response.text}"
        )
    grant = CapabilityGrant.from_b64(issue_response.json()["grant"])
    if relay_issuance_public is not None:
        verify_capability_grant(
            grant,
            relay_signing_public=relay_issuance_public,
            relay_name=relay_name,
            relay_tls_spki_sha256=tls_pin,
        )
    store.save_capability_grant(
        relay_name=relay_name,
        grant=grant,
        auth_private=auth_private,
        issuance_salt=issuance_salt,
        relay_tls_spki_sha256=tls_pin,
    )
    return CapabilitySession(grant=grant, auth_private=auth_private)


def ensure_capability_session(
    relay_url: str,
    relay_name: str,
    *,
    identity: Identity,
    contact: Contact,
    store: FileLocalStore,
    permissions: tuple[str, ...] = DEFAULT_CAPABILITY_PERMISSIONS,
) -> CapabilitySession:
    """Return a valid capability session, refreshing from relay when expired."""
    tls_pin = _relay_tls_pin(relay_url, store=store, contact=contact)
    now_ms = int(time.time() * 1000)
    stored = store.load_capability_grant(relay_name)
    if stored is not None:
        grant = CapabilityGrant.from_bytes(b64decode(stored["grant_b64"]))
        auth_private = ed25519.Ed25519PrivateKey.from_private_bytes(
            b64decode(stored["auth_private_b64"])
        )
        if grant.expires_at > now_ms + 60_000 and grant.relay_tls_spki_sha256 == tls_pin:
            missing = [item for item in permissions if item not in grant.permissions]
            if not missing:
                return CapabilitySession(grant=grant, auth_private=auth_private)
    return issue_capability_from_relay(
        relay_url,
        relay_name,
        identity=identity,
        contact=contact,
        store=store,
        permissions=permissions,
    )


def capability_headers_for_request(
    session: CapabilitySession,
    *,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    return capability_request_headers(
        session.grant,
        session.auth_private,
        method=method,
        path=path,
        body=body,
    )


def relay_name_for_url(
    relay_url: str,
    network: dict | None = None,
    *,
    default: str = "relay",
) -> str:
    normalized = endpoint_base_url(relay_url)
    if network is not None:
        for node in network.values():
            if endpoint_base_url(node.url) == normalized:
                return node.name
    return os.environ.get("YAKR_RELAY_NAME", default)


def provision_contact_relay_capabilities(
    store: FileLocalStore,
    identity: Identity,
    contact: Contact,
    *,
    relay_url: str | None = None,
    relay_name: str | None = None,
) -> CapabilitySession | None:
    """Issue and persist capability grants for one paired relay operator contact."""
    if contact.delivery_profile is None:
        return None
    descriptors = mailbox_descriptors(contact.delivery_profile)
    if not descriptors:
        return None
    descriptor = descriptors[0]
    target_url = (relay_url or descriptor.url).rstrip("/")
    target_name = relay_name or descriptor.name
    try:
        return issue_capability_from_relay(
            target_url,
            target_name,
            identity=identity,
            contact=contact,
            store=store,
        )
    except (RuntimeError, ValueError, OSError):
        return None


def try_provision_pairing_capabilities(
    store: FileLocalStore,
    identity: Identity,
    contact: Contact,
) -> list[CapabilitySession]:
    """Best-effort capability bootstrap for relay operators learned during pairing."""
    sessions: list[CapabilitySession] = []
    if contact.delivery_profile is None:
        return sessions
    for descriptor in mailbox_descriptors(contact.delivery_profile):
        session = provision_contact_relay_capabilities(
            store,
            identity,
            contact,
            relay_url=descriptor.url,
            relay_name=descriptor.name,
        )
        if session is not None:
            sessions.append(session)
    return sessions


def bootstrap_operator_capabilities(
    owner_store: FileLocalStore,
    identity: Identity,
    operator_name: str,
    *,
    relay_url: str,
    explicit_pin: bytes | None = None,
) -> CapabilitySession | None:
    """Bootstrap capability grants after operator pairing when the relay is reachable."""
    contact = owner_store.get_contact(operator_name)
    if contact is None:
        raise ValueError(f"unknown operator contact: {operator_name}")
    if explicit_pin is not None:
        _ = explicit_pin
    return provision_contact_relay_capabilities(
        owner_store,
        identity,
        contact,
        relay_url=relay_url,
        relay_name=operator_name,
    )
