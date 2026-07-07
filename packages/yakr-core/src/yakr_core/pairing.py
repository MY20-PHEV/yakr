from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.crypto import hkdf_derive, x25519_shared_secret
from yakr_core.delivery_profile import DeliveryProfile, verify_delivery_profile
from yakr_core.hybrid_pq import derive_hybrid_master, kem_decapsulate, kem_encapsulate
from yakr_core.identity import Contact, Identity, conversation_id_for
from yakr_core.invite import InviteBundle, invite_supports_hybrid
from yakr_core.ratchet import RatchetState


PAIR_MASTER_INFO = b"yakr/v0.4/pair-master"


@dataclass(frozen=True)
class PairingRequest:
    invite_secret: bytes
    joiner_name: str
    joiner_signing_public: bytes
    joiner_agreement_public: bytes
    joiner_ephemeral_public: bytes
    joiner_profile: bytes = b""
    kem_ciphertext: bytes = b""

    def to_bytes(self) -> bytes:
        payload: dict[str, bytes | str] = {
            "invite_secret": self.invite_secret,
            "joiner_name": self.joiner_name,
            "joiner_signing_public": self.joiner_signing_public,
            "joiner_agreement_public": self.joiner_agreement_public,
            "joiner_ephemeral_public": self.joiner_ephemeral_public,
            "joiner_profile": self.joiner_profile,
        }
        if self.kem_ciphertext:
            payload["kem_ciphertext"] = self.kem_ciphertext
        return cbor2.dumps(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingRequest:
        payload = cbor2.loads(data)
        return cls(
            invite_secret=bytes(payload["invite_secret"]),
            joiner_name=str(payload["joiner_name"]),
            joiner_signing_public=bytes(payload["joiner_signing_public"]),
            joiner_agreement_public=bytes(payload["joiner_agreement_public"]),
            joiner_ephemeral_public=bytes(payload["joiner_ephemeral_public"]),
            joiner_profile=bytes(payload.get("joiner_profile", b"")),
            kem_ciphertext=bytes(payload.get("kem_ciphertext", b"")),
        )


@dataclass(frozen=True)
class PairingResponse:
    inviter_ephemeral_public: bytes
    transcript_hash: bytes
    inviter_profile: bytes = b""

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "inviter_ephemeral_public": self.inviter_ephemeral_public,
                "transcript_hash": self.transcript_hash,
                "inviter_profile": self.inviter_profile,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingResponse:
        payload = cbor2.loads(data)
        return cls(
            inviter_ephemeral_public=bytes(payload["inviter_ephemeral_public"]),
            transcript_hash=bytes(payload["transcript_hash"]),
            inviter_profile=bytes(payload.get("inviter_profile", b"")),
        )


@dataclass(frozen=True)
class PairingSecrets:
    ephemeral_private: x25519.X25519PrivateKey
    pq_secret: bytes | None = None


def build_pairing_request(
    identity: Identity,
    invite: InviteBundle,
    joiner_name: str,
    *,
    joiner_profile: bytes = b"",
) -> tuple[PairingRequest, PairingSecrets]:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    kem_ciphertext = b""
    pq_secret: bytes | None = None
    if invite_supports_hybrid(invite):
        kem_ciphertext, pq_secret = kem_encapsulate(invite.kem_public)
    request = PairingRequest(
        invite_secret=invite.invite_secret,
        joiner_name=joiner_name,
        joiner_signing_public=identity.signing_public_bytes,
        joiner_agreement_public=identity.agreement_public_bytes,
        joiner_ephemeral_public=ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        joiner_profile=joiner_profile,
        kem_ciphertext=kem_ciphertext,
    )
    return request, PairingSecrets(ephemeral_private=ephemeral_private, pq_secret=pq_secret)


def pairing_transcript(
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_public: bytes,
) -> bytes:
    parts = [
        invite.invite_secret,
        invite.signing_public,
        invite.agreement_public,
        request.joiner_signing_public,
        request.joiner_agreement_public,
        request.joiner_ephemeral_public,
        inviter_ephemeral_public,
    ]
    if request.kem_ciphertext:
        parts.append(request.kem_ciphertext)
    return hashlib.sha256(b"|".join(parts)).digest()


def derive_pair_master(
    *,
    inviter_agreement_private: x25519.X25519PrivateKey,
    joiner_agreement_public: bytes,
    inviter_ephemeral_private: x25519.X25519PrivateKey,
    joiner_ephemeral_public: bytes,
    transcript_hash: bytes,
    pq_secret: bytes | None = None,
) -> bytes:
    identity_shared = x25519_shared_secret(inviter_agreement_private, joiner_agreement_public)
    ephemeral_shared = x25519_shared_secret(inviter_ephemeral_private, joiner_ephemeral_public)
    if pq_secret is not None:
        return derive_hybrid_master(
            identity_shared=identity_shared,
            ephemeral_shared=ephemeral_shared,
            pq_secret=pq_secret,
            transcript_hash=transcript_hash,
        )
    return hkdf_derive(
        identity_shared + ephemeral_shared,
        PAIR_MASTER_INFO,
        salt=transcript_hash,
    )


def derive_pair_master_joiner(
    *,
    joiner_agreement_private: x25519.X25519PrivateKey,
    inviter_agreement_public: bytes,
    joiner_ephemeral_private: x25519.X25519PrivateKey,
    inviter_ephemeral_public: bytes,
    transcript_hash: bytes,
    pq_secret: bytes | None = None,
) -> bytes:
    identity_shared = x25519_shared_secret(joiner_agreement_private, inviter_agreement_public)
    ephemeral_shared = x25519_shared_secret(joiner_ephemeral_private, inviter_ephemeral_public)
    if pq_secret is not None:
        return derive_hybrid_master(
            identity_shared=identity_shared,
            ephemeral_shared=ephemeral_shared,
            pq_secret=pq_secret,
            transcript_hash=transcript_hash,
        )
    return hkdf_derive(
        identity_shared + ephemeral_shared,
        PAIR_MASTER_INFO,
        salt=transcript_hash,
    )


def contact_id_for(signing_public: bytes, agreement_public: bytes) -> bytes:
    return hashlib.sha256(signing_public + agreement_public).digest()


def profile_from_pairing_bytes(data: bytes, signing_public: bytes) -> DeliveryProfile | None:
    if not data:
        return None
    profile = DeliveryProfile.from_bytes(data)
    verify_delivery_profile(profile, signing_public)
    return profile


def inviter_complete_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_private: x25519.X25519PrivateKey,
    *,
    inviter_profile: bytes = b"",
) -> tuple[PairingResponse, Contact]:
    inviter_ephemeral_public = inviter_ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_hash = pairing_transcript(invite, request, inviter_ephemeral_public)
    pq_secret = None
    hybrid = False
    if invite_supports_hybrid(invite):
        if not request.kem_ciphertext:
            raise ValueError("hybrid invite requires kem ciphertext")
        if not identity.kem_private:
            raise ValueError("inviter missing ML-KEM secret key")
        pq_secret = kem_decapsulate(identity.kem_private, request.kem_ciphertext)
        hybrid = True
    master = derive_pair_master(
        inviter_agreement_private=identity.agreement_private,
        joiner_agreement_public=request.joiner_agreement_public,
        inviter_ephemeral_private=inviter_ephemeral_private,
        joiner_ephemeral_public=request.joiner_ephemeral_public,
        transcript_hash=transcript_hash,
        pq_secret=pq_secret,
    )
    now = int(time.time() * 1000)
    contact = Contact(
        name=request.joiner_name,
        signing_public=request.joiner_signing_public,
        agreement_public=request.joiner_agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(identity.name, request.joiner_name),
        contact_id=contact_id_for(request.joiner_signing_public, request.joiner_agreement_public),
        transcript_hash=transcript_hash,
        ratchet=RatchetState.from_master(master, is_initiator=True, hybrid=hybrid),
        delivery_profile=profile_from_pairing_bytes(
            request.joiner_profile,
            request.joiner_signing_public,
        ),
        hybrid_pq=hybrid,
        session_started_at=now,
    )
    response = PairingResponse(
        inviter_ephemeral_public=inviter_ephemeral_public,
        transcript_hash=transcript_hash,
        inviter_profile=inviter_profile,
    )
    return response, contact


def joiner_complete_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    secrets: PairingSecrets,
    response: PairingResponse,
) -> Contact:
    if response.transcript_hash != pairing_transcript(invite, request, response.inviter_ephemeral_public):
        raise ValueError("pairing transcript mismatch")
    hybrid = invite_supports_hybrid(invite)
    pq_secret = secrets.pq_secret if hybrid else None
    if hybrid and pq_secret is None:
        raise ValueError("missing PQ shared secret for hybrid pairing")
    master = derive_pair_master_joiner(
        joiner_agreement_private=identity.agreement_private,
        inviter_agreement_public=invite.agreement_public,
        joiner_ephemeral_private=secrets.ephemeral_private,
        inviter_ephemeral_public=response.inviter_ephemeral_public,
        transcript_hash=response.transcript_hash,
        pq_secret=pq_secret,
    )
    now = int(time.time() * 1000)
    return Contact(
        name=invite.inviter_name,
        signing_public=invite.signing_public,
        agreement_public=invite.agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(invite.inviter_name, identity.name),
        contact_id=contact_id_for(invite.signing_public, invite.agreement_public),
        transcript_hash=response.transcript_hash,
        ratchet=RatchetState.from_master(master, is_initiator=False, hybrid=hybrid),
        delivery_profile=profile_from_pairing_bytes(
            response.inviter_profile,
            invite.signing_public,
        ),
        hybrid_pq=hybrid,
        session_started_at=now,
    )
