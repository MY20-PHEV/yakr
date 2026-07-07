from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from yakr_core.crypto import hkdf_derive, x25519_shared_secret
from yakr_core.identity import Contact, Identity, conversation_id_for
from yakr_core.invite import InviteBundle
from yakr_core.ratchet import RatchetState


PAIR_MASTER_INFO = b"yakr/v0.4/pair-master"


@dataclass(frozen=True)
class PairingRequest:
    invite_secret: bytes
    joiner_name: str
    joiner_signing_public: bytes
    joiner_agreement_public: bytes
    joiner_ephemeral_public: bytes

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "invite_secret": self.invite_secret,
                "joiner_name": self.joiner_name,
                "joiner_signing_public": self.joiner_signing_public,
                "joiner_agreement_public": self.joiner_agreement_public,
                "joiner_ephemeral_public": self.joiner_ephemeral_public,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingRequest:
        payload = cbor2.loads(data)
        return cls(
            invite_secret=bytes(payload["invite_secret"]),
            joiner_name=str(payload["joiner_name"]),
            joiner_signing_public=bytes(payload["joiner_signing_public"]),
            joiner_agreement_public=bytes(payload["joiner_agreement_public"]),
            joiner_ephemeral_public=bytes(payload["joiner_ephemeral_public"]),
        )


@dataclass(frozen=True)
class PairingResponse:
    inviter_ephemeral_public: bytes
    transcript_hash: bytes

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "inviter_ephemeral_public": self.inviter_ephemeral_public,
                "transcript_hash": self.transcript_hash,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingResponse:
        payload = cbor2.loads(data)
        return cls(
            inviter_ephemeral_public=bytes(payload["inviter_ephemeral_public"]),
            transcript_hash=bytes(payload["transcript_hash"]),
        )


def build_pairing_request(identity: Identity, invite: InviteBundle, joiner_name: str) -> tuple[PairingRequest, x25519.X25519PrivateKey]:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    request = PairingRequest(
        invite_secret=invite.invite_secret,
        joiner_name=joiner_name,
        joiner_signing_public=identity.signing_public_bytes,
        joiner_agreement_public=identity.agreement_public_bytes,
        joiner_ephemeral_public=ephemeral_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )
    return request, ephemeral_private


def pairing_transcript(
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_public: bytes,
) -> bytes:
    material = b"|".join(
        [
            invite.invite_secret,
            invite.signing_public,
            invite.agreement_public,
            request.joiner_signing_public,
            request.joiner_agreement_public,
            request.joiner_ephemeral_public,
            inviter_ephemeral_public,
        ]
    )
    return hashlib.sha256(material).digest()


def derive_pair_master(
    *,
    inviter_agreement_private: x25519.X25519PrivateKey,
    joiner_agreement_public: bytes,
    inviter_ephemeral_private: x25519.X25519PrivateKey,
    joiner_ephemeral_public: bytes,
    transcript_hash: bytes,
) -> bytes:
    identity_shared = x25519_shared_secret(inviter_agreement_private, joiner_agreement_public)
    ephemeral_shared = x25519_shared_secret(inviter_ephemeral_private, joiner_ephemeral_public)
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
) -> bytes:
    identity_shared = x25519_shared_secret(joiner_agreement_private, inviter_agreement_public)
    ephemeral_shared = x25519_shared_secret(joiner_ephemeral_private, inviter_ephemeral_public)
    return hkdf_derive(
        identity_shared + ephemeral_shared,
        PAIR_MASTER_INFO,
        salt=transcript_hash,
    )


def contact_id_for(signing_public: bytes, agreement_public: bytes) -> bytes:
    return hashlib.sha256(signing_public + agreement_public).digest()


def inviter_complete_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_private: x25519.X25519PrivateKey,
) -> tuple[PairingResponse, Contact]:
    inviter_ephemeral_public = inviter_ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_hash = pairing_transcript(invite, request, inviter_ephemeral_public)
    master = derive_pair_master(
        inviter_agreement_private=identity.agreement_private,
        joiner_agreement_public=request.joiner_agreement_public,
        inviter_ephemeral_private=inviter_ephemeral_private,
        joiner_ephemeral_public=request.joiner_ephemeral_public,
        transcript_hash=transcript_hash,
    )
    contact = Contact(
        name=request.joiner_name,
        signing_public=request.joiner_signing_public,
        agreement_public=request.joiner_agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(identity.name, request.joiner_name),
        contact_id=contact_id_for(request.joiner_signing_public, request.joiner_agreement_public),
        transcript_hash=transcript_hash,
        ratchet=RatchetState.from_master(master, is_initiator=True),
    )
    response = PairingResponse(
        inviter_ephemeral_public=inviter_ephemeral_public,
        transcript_hash=transcript_hash,
    )
    return response, contact


def joiner_complete_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    joiner_ephemeral_private: x25519.X25519PrivateKey,
    response: PairingResponse,
) -> Contact:
    if response.transcript_hash != pairing_transcript(invite, request, response.inviter_ephemeral_public):
        raise ValueError("pairing transcript mismatch")
    master = derive_pair_master_joiner(
        joiner_agreement_private=identity.agreement_private,
        inviter_agreement_public=invite.agreement_public,
        joiner_ephemeral_private=joiner_ephemeral_private,
        inviter_ephemeral_public=response.inviter_ephemeral_public,
        transcript_hash=response.transcript_hash,
    )
    return Contact(
        name=invite.inviter_name,
        signing_public=invite.signing_public,
        agreement_public=invite.agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(invite.inviter_name, identity.name),
        contact_id=contact_id_for(invite.signing_public, invite.agreement_public),
        transcript_hash=response.transcript_hash,
        ratchet=RatchetState.from_master(master, is_initiator=False),
    )
