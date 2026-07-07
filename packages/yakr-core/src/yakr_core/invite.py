from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.identity import Identity, b64encode, b64decode


PROTOCOL_V4 = "yakr-v0.4"
DEFAULT_INVITE_TTL_MS = 24 * 60 * 60 * 1000


@dataclass(frozen=True)
class InviteBundle:
    protocol: str
    inviter_name: str
    signing_public: bytes
    agreement_public: bytes
    invite_secret: bytes
    rendezvous_hint: str
    expires_at: int
    capabilities: tuple[str, ...]
    signature: bytes

    def unsigned_payload(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": self.protocol,
                "inviter_name": self.inviter_name,
                "signing_public": self.signing_public,
                "agreement_public": self.agreement_public,
                "invite_secret": self.invite_secret,
                "rendezvous_hint": self.rendezvous_hint,
                "expires_at": self.expires_at,
                "capabilities": list(self.capabilities),
            }
        )

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": self.protocol,
                "inviter_name": self.inviter_name,
                "signing_public": self.signing_public,
                "agreement_public": self.agreement_public,
                "invite_secret": self.invite_secret,
                "rendezvous_hint": self.rendezvous_hint,
                "expires_at": self.expires_at,
                "capabilities": list(self.capabilities),
                "signature": self.signature,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> InviteBundle:
        payload = cbor2.loads(data)
        return cls(
            protocol=str(payload["protocol"]),
            inviter_name=str(payload["inviter_name"]),
            signing_public=bytes(payload["signing_public"]),
            agreement_public=bytes(payload["agreement_public"]),
            invite_secret=bytes(payload["invite_secret"]),
            rendezvous_hint=str(payload["rendezvous_hint"]),
            expires_at=int(payload["expires_at"]),
            capabilities=tuple(str(item) for item in payload["capabilities"]),
            signature=bytes(payload["signature"]),
        )


def create_invite(
    identity: Identity,
    *,
    rendezvous_hint: str,
    ttl_ms: int = DEFAULT_INVITE_TTL_MS,
) -> InviteBundle:
    unsigned = {
        "protocol": PROTOCOL_V4,
        "inviter_name": identity.name,
        "signing_public": identity.signing_public_bytes,
        "agreement_public": identity.agreement_public_bytes,
        "invite_secret": secrets.token_bytes(32),
        "rendezvous_hint": rendezvous_hint,
        "expires_at": int(time.time() * 1000) + ttl_ms,
        "capabilities": ["direct_p2p", "friend_relay", "store_forward"],
    }
    payload = cbor2.dumps(unsigned)
    signature = identity.signing_private.sign(payload)
    return InviteBundle(
        protocol=unsigned["protocol"],
        inviter_name=unsigned["inviter_name"],
        signing_public=unsigned["signing_public"],
        agreement_public=unsigned["agreement_public"],
        invite_secret=unsigned["invite_secret"],
        rendezvous_hint=unsigned["rendezvous_hint"],
        expires_at=unsigned["expires_at"],
        capabilities=tuple(unsigned["capabilities"]),
        signature=bytes(signature),
    )


def verify_invite(bundle: InviteBundle) -> None:
    if bundle.protocol != PROTOCOL_V4:
        raise ValueError("unsupported invite protocol")
    if bundle.expires_at <= int(time.time() * 1000):
        raise ValueError("invite expired")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(bundle.signing_public)
    public_key.verify(bundle.signature, bundle.unsigned_payload())


def invite_to_url(bundle: InviteBundle) -> str:
    encoded = base64.urlsafe_b64encode(bundle.to_bytes()).decode("ascii").rstrip("=")
    return f"yakr://invite/{encoded}"


def invite_from_url(url: str) -> InviteBundle:
    prefix = "yakr://invite/"
    if not url.startswith(prefix):
        raise ValueError("invalid invite url")
    return InviteBundle.from_bytes(b64decode(url[len(prefix) :]))


def safety_code(bundle: InviteBundle) -> str:
    digest = hashlib.sha256(bundle.signing_public + bundle.agreement_public).digest()
    digits = "".join(str(byte % 10) for byte in digest[:10])
    return f"{digits[0:4]} {digits[4:8]} {digits[8:10]}"
