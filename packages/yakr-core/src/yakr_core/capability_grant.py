"""Relay capability grants (ADR 012 / relay-capability-v1)."""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.crypto import hkdf_derive
from yakr_core.identity import b64decode, b64encode

GRANT_PROTOCOL = "yakr-relay-capability-grant-v1"
CAPABILITY_HKDF_INFO = b"yakr-relay-capability-v1"
DEFAULT_CAPABILITY_TTL_MS = 24 * 60 * 60 * 1000
TIMESTAMP_SKEW_MS = 5 * 60 * 1000

TICKET_PERMISSION_ALIASES = {
    "store": "post",
    "forward": "forward",
}


def normalize_permission(permission: str) -> str:
    return TICKET_PERMISSION_ALIASES.get(permission, permission)


@dataclass(frozen=True)
class CapabilityGrant:
    capability_id: bytes
    capability_generation: int
    relay_name: str
    relay_tls_spki_sha256: bytes
    permissions: tuple[str, ...]
    expires_at: int
    auth_public: bytes
    relay_signature: bytes

    def unsigned_payload(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": GRANT_PROTOCOL,
                "capability_id": self.capability_id,
                "capability_generation": self.capability_generation,
                "relay_name": self.relay_name,
                "relay_tls_spki_sha256": self.relay_tls_spki_sha256,
                "permissions": list(self.permissions),
                "expires_at": self.expires_at,
                "auth_public": self.auth_public,
            }
        )

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": GRANT_PROTOCOL,
                "capability_id": self.capability_id,
                "capability_generation": self.capability_generation,
                "relay_name": self.relay_name,
                "relay_tls_spki_sha256": self.relay_tls_spki_sha256,
                "permissions": list(self.permissions),
                "expires_at": self.expires_at,
                "auth_public": self.auth_public,
                "relay_signature": self.relay_signature,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> CapabilityGrant:
        payload = cbor2.loads(data)
        if str(payload.get("protocol")) != GRANT_PROTOCOL:
            raise ValueError("unsupported capability grant protocol")
        return cls(
            capability_id=bytes(payload["capability_id"]),
            capability_generation=int(payload["capability_generation"]),
            relay_name=str(payload["relay_name"]),
            relay_tls_spki_sha256=bytes(payload["relay_tls_spki_sha256"]),
            permissions=tuple(str(item) for item in payload["permissions"]),
            expires_at=int(payload["expires_at"]),
            auth_public=bytes(payload["auth_public"]),
            relay_signature=bytes(payload["relay_signature"]),
        )

    def to_b64(self) -> str:
        return b64encode(self.to_bytes())

    @classmethod
    def from_b64(cls, value: str) -> CapabilityGrant:
        return cls.from_bytes(b64decode(value))


def derive_capability_material(
    master_secret: bytes,
    *,
    relay_name: str,
    relay_tls_spki_sha256: bytes,
    capability_generation: int,
    issuance_salt: bytes,
) -> tuple[bytes, ed25519.Ed25519PrivateKey]:
    """Derive per-relay capability id and client auth keypair."""
    if len(issuance_salt) != 16:
        raise ValueError("issuance_salt must be 16 bytes")
    seed_material = (
        relay_name.encode("utf-8")
        + relay_tls_spki_sha256
        + capability_generation.to_bytes(8, "big")
        + issuance_salt
    )
    capability_seed = hkdf_derive(master_secret, CAPABILITY_HKDF_INFO, salt=seed_material)
    capability_id = hkdf_derive(capability_seed, b"id", length=16)
    auth_seed = hkdf_derive(capability_seed, b"auth", length=32)
    auth_private = ed25519.Ed25519PrivateKey.from_private_bytes(auth_seed)
    return capability_id, auth_private


def issue_capability_grant(
    relay_signing_private: ed25519.Ed25519PrivateKey,
    *,
    capability_id: bytes,
    capability_generation: int,
    relay_name: str,
    relay_tls_spki_sha256: bytes,
    permissions: tuple[str, ...],
    auth_public: bytes,
    ttl_ms: int = DEFAULT_CAPABILITY_TTL_MS,
    now_ms: int | None = None,
) -> CapabilityGrant:
    """Relay operator signs a capability grant for a registered auth public key."""
    if len(capability_id) != 16:
        raise ValueError("capability_id must be 16 bytes")
    if len(relay_tls_spki_sha256) != 32:
        raise ValueError("relay_tls_spki_sha256 must be 32 bytes")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    grant = CapabilityGrant(
        capability_id=capability_id,
        capability_generation=capability_generation,
        relay_name=relay_name,
        relay_tls_spki_sha256=relay_tls_spki_sha256,
        permissions=tuple(permissions),
        expires_at=now + ttl_ms,
        auth_public=auth_public,
        relay_signature=b"",
    )
    signature = relay_signing_private.sign(grant.unsigned_payload())
    return CapabilityGrant(
        capability_id=grant.capability_id,
        capability_generation=grant.capability_generation,
        relay_name=grant.relay_name,
        relay_tls_spki_sha256=grant.relay_tls_spki_sha256,
        permissions=grant.permissions,
        expires_at=grant.expires_at,
        auth_public=grant.auth_public,
        relay_signature=bytes(signature),
    )


def verify_capability_grant(
    grant: CapabilityGrant,
    *,
    relay_signing_public: bytes,
    relay_name: str,
    relay_tls_spki_sha256: bytes,
    now_ms: int | None = None,
) -> None:
    """Verify relay issuance signature and grant metadata."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if grant.expires_at <= now:
        raise ValueError("capability grant expired")
    if grant.relay_name != relay_name:
        raise ValueError("capability grant relay name mismatch")
    if grant.relay_tls_spki_sha256 != relay_tls_spki_sha256:
        raise ValueError("capability grant TLS pin mismatch")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(relay_signing_public)
    public_key.verify(grant.relay_signature, grant.unsigned_payload())


def capability_request_signing_input(
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp_ms: int,
    nonce: bytes,
) -> bytes:
    body_hash = hashlib.sha256(body).digest()
    return b"\n".join(
        [
            method.upper().encode("utf-8"),
            path.encode("utf-8"),
            body_hash,
            str(timestamp_ms).encode("utf-8"),
            nonce,
        ]
    )


def sign_capability_request(
    auth_private: ed25519.Ed25519PrivateKey,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp_ms: int | None = None,
    nonce: bytes | None = None,
) -> tuple[int, bytes, bytes]:
    """Return (timestamp_ms, nonce, signature) for request authorization headers."""
    ts = int(time.time() * 1000) if timestamp_ms is None else timestamp_ms
    raw_nonce = nonce or secrets.token_bytes(16)
    if len(raw_nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    signing_input = capability_request_signing_input(
        method=method,
        path=path,
        body=body,
        timestamp_ms=ts,
        nonce=raw_nonce,
    )
    return ts, raw_nonce, bytes(auth_private.sign(signing_input))


def verify_capability_request(
    grant: CapabilityGrant,
    *,
    auth_public: bytes,
    signature: bytes,
    method: str,
    path: str,
    body: bytes,
    timestamp_ms: int,
    nonce: bytes,
    now_ms: int | None = None,
) -> None:
    """Verify client proof-of-possession for one HTTP request."""
    if auth_public != grant.auth_public:
        raise ValueError("capability auth public key mismatch")
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if abs(timestamp_ms - now) > TIMESTAMP_SKEW_MS:
        raise ValueError("capability request timestamp out of range")
    if len(nonce) != 16:
        raise ValueError("nonce must be 16 bytes")
    signing_input = capability_request_signing_input(
        method=method,
        path=path,
        body=body,
        timestamp_ms=timestamp_ms,
        nonce=nonce,
    )
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(auth_public)
    public_key.verify(signature, signing_input)


def grant_allows_permission(grant: CapabilityGrant, permission: str) -> bool:
    normalized = normalize_permission(permission)
    return normalized in grant.permissions or permission in grant.permissions


def capability_request_headers(
    grant: CapabilityGrant,
    auth_private: ed25519.Ed25519PrivateKey,
    *,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    """Build HTTP headers for an authorized relay request."""
    timestamp_ms, nonce, signature = sign_capability_request(
        auth_private,
        method=method,
        path=path,
        body=body,
    )
    return {
        "Yakr-Capability-Grant": grant.to_b64(),
        "Yakr-Capability-Timestamp": str(timestamp_ms),
        "Yakr-Capability-Nonce": b64encode(nonce),
        "Yakr-Capability-Signature": b64encode(signature),
    }
