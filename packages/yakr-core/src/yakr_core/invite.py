from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.hybrid_pq import HYBRID_PQ_CAPABILITY
from yakr_core.identity import Identity, b64decode, b64encode


PROTOCOL_V4 = "yakr-v0.4"
PROTOCOL_V6 = "yakr-v0.6"
SUPPORTED_PROTOCOLS = {PROTOCOL_V4, PROTOCOL_V6}
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
    kem_public: bytes = b""
    pq_signing_public: bytes = b""
    pq_signature: bytes = b""

    def _unsigned_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "protocol": self.protocol,
            "inviter_name": self.inviter_name,
            "signing_public": self.signing_public,
            "agreement_public": self.agreement_public,
            "invite_secret": self.invite_secret,
            "rendezvous_hint": self.rendezvous_hint,
            "expires_at": self.expires_at,
            "capabilities": list(self.capabilities),
        }
        if self.kem_public:
            payload["kem_public"] = self.kem_public
        if self.pq_signing_public:
            payload["pq_signing_public"] = self.pq_signing_public
        return payload

    def unsigned_payload(self) -> bytes:
        return cbor2.dumps(self._unsigned_dict())

    def to_bytes(self) -> bytes:
        payload = self._unsigned_dict()
        payload["signature"] = self.signature
        if self.pq_signature:
            payload["pq_signature"] = self.pq_signature
        return cbor2.dumps(payload)

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
            kem_public=bytes(payload.get("kem_public", b"")),
            pq_signing_public=bytes(payload.get("pq_signing_public", b"")),
            pq_signature=bytes(payload.get("pq_signature", b"")),
        )


def invite_supports_hybrid(bundle: InviteBundle) -> bool:
    return HYBRID_PQ_CAPABILITY in bundle.capabilities and bool(bundle.kem_public)


def create_invite(
    identity: Identity,
    *,
    rendezvous_hint: str,
    ttl_ms: int = DEFAULT_INVITE_TTL_MS,
    hybrid_pq: bool = False,
) -> InviteBundle:
    capabilities = ["direct_p2p", "friend_relay", "store_forward"]
    protocol = PROTOCOL_V4
    kem_public = b""
    pq_signing_public = b""
    pq_signature = b""

    if hybrid_pq:
        if not identity.kem_public:
            raise ValueError("identity missing ML-KEM keypair for hybrid invite")
        protocol = PROTOCOL_V6
        capabilities.append(HYBRID_PQ_CAPABILITY)
        kem_public = identity.kem_public
        if identity.pq_signing_private:
            from pqcrypto.sign.ml_dsa_65 import sign as pq_sign

            pq_signing_public = identity.pq_signing_public
            unsigned = {
                "protocol": protocol,
                "inviter_name": identity.name,
                "signing_public": identity.signing_public_bytes,
                "agreement_public": identity.agreement_public_bytes,
                "invite_secret": secrets.token_bytes(32),
                "rendezvous_hint": rendezvous_hint,
                "expires_at": int(time.time() * 1000) + ttl_ms,
                "capabilities": capabilities,
                "kem_public": kem_public,
                "pq_signing_public": pq_signing_public,
            }
            payload = cbor2.dumps(unsigned)
            signature = identity.signing_private.sign(payload)
            pq_signature = pq_sign(identity.pq_signing_private, payload)
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
                kem_public=kem_public,
                pq_signing_public=pq_signing_public,
                pq_signature=pq_signature,
            )

    unsigned = {
        "protocol": protocol,
        "inviter_name": identity.name,
        "signing_public": identity.signing_public_bytes,
        "agreement_public": identity.agreement_public_bytes,
        "invite_secret": secrets.token_bytes(32),
        "rendezvous_hint": rendezvous_hint,
        "expires_at": int(time.time() * 1000) + ttl_ms,
        "capabilities": capabilities,
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
        kem_public=kem_public,
        pq_signing_public=pq_signing_public,
        pq_signature=pq_signature,
    )


def verify_invite(bundle: InviteBundle) -> None:
    if bundle.protocol not in SUPPORTED_PROTOCOLS:
        raise ValueError("unsupported invite protocol")
    if bundle.expires_at <= int(time.time() * 1000):
        raise ValueError("invite expired")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(bundle.signing_public)
    public_key.verify(bundle.signature, bundle.unsigned_payload())
    if bundle.pq_signature:
        if not bundle.pq_signing_public:
            raise ValueError("invite missing PQ signing public key")
        from pqcrypto.sign.ml_dsa_65 import verify as pq_verify

        if not pq_verify(bundle.pq_signing_public, bundle.unsigned_payload(), bundle.pq_signature):
            raise ValueError("invalid PQ invite signature")


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
