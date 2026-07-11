from __future__ import annotations

import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.identity import Identity, b64encode, b64decode


@dataclass(frozen=True)
class RelayTicket:
    issuer_signing_public: bytes
    relay_name: str
    permissions: tuple[str, ...]
    contact_id: bytes
    expires_at: int
    signature: bytes

    def unsigned_payload(self) -> bytes:
        return cbor2.dumps(
            {
                "issuer_signing_public": self.issuer_signing_public,
                "relay_name": self.relay_name,
                "permissions": list(self.permissions),
                "contact_id": self.contact_id,
                "expires_at": self.expires_at,
            }
        )

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "issuer_signing_public": self.issuer_signing_public,
                "relay_name": self.relay_name,
                "permissions": list(self.permissions),
                "contact_id": self.contact_id,
                "expires_at": self.expires_at,
                "signature": self.signature,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RelayTicket:
        payload = cbor2.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("invalid relay ticket")
        return cls(
            issuer_signing_public=bytes(payload["issuer_signing_public"]),
            relay_name=str(payload["relay_name"]),
            permissions=tuple(str(item) for item in payload["permissions"]),
            contact_id=bytes(payload["contact_id"]),
            expires_at=int(payload["expires_at"]),
            signature=bytes(payload["signature"]),
        )

    def to_b64(self) -> str:
        return b64encode(self.to_bytes())

    @classmethod
    def from_b64(cls, value: str) -> RelayTicket:
        return cls.from_bytes(b64decode(value))


def issue_relay_ticket(
    identity: Identity,
    *,
    relay_name: str,
    permissions: tuple[str, ...],
    contact_id: bytes,
    ttl_ms: int = 60 * 60 * 1000,
) -> RelayTicket:
    unsigned = {
        "issuer_signing_public": identity.signing_public_bytes,
        "relay_name": relay_name,
        "permissions": list(permissions),
        "contact_id": contact_id,
        "expires_at": int(time.time() * 1000) + ttl_ms,
    }
    payload = cbor2.dumps(unsigned)
    signature = identity.signing_private.sign(payload)
    return RelayTicket(
        issuer_signing_public=unsigned["issuer_signing_public"],
        relay_name=relay_name,
        permissions=tuple(permissions),
        contact_id=contact_id,
        expires_at=unsigned["expires_at"],
        signature=bytes(signature),
    )


def verify_relay_ticket(ticket: RelayTicket, *, relay_name: str, permission: str) -> None:
    if ticket.expires_at <= int(time.time() * 1000):
        raise ValueError("relay ticket expired")
    if ticket.relay_name != relay_name:
        raise ValueError("relay ticket name mismatch")
    if permission not in ticket.permissions:
        raise ValueError("relay ticket missing permission")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(ticket.issuer_signing_public)
    public_key.verify(ticket.signature, ticket.unsigned_payload())
