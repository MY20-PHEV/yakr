from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.crypto import hkdf_derive, x25519_shared_secret
from yakr_core.delivery_profile import DeliveryProfile, verify_delivery_profile
from yakr_core.profile_ack import apply_peer_profile_ack_from_bytes
from yakr_core.hybrid_pq import derive_hybrid_master, kem_decapsulate, kem_encapsulate
from yakr_core.identity import Contact, Identity, b64decode, b64encode, conversation_id_for
from yakr_core.invite import InviteBundle, invite_supports_hybrid
from yakr_core.ratchet import RatchetState


PAIR_MASTER_INFO = b"yakr/v0.4/pair-master"
PAIR_REQUEST_PREFIX = "yakr://pair-request/"
PAIR_RESPONSE_PREFIX = "yakr://pair-response/"
OFFLINE_RENDEZVOUS_HINT = "offline://qr"


def invite_tag_for_secret(invite_secret: bytes) -> str:
    import hashlib

    from yakr_core.identity import b64encode

    if len(invite_secret) != 32:
        raise ValueError("invite_secret must be 32 bytes")
    return b64encode(hashlib.sha256(invite_secret).digest())


@dataclass(frozen=True)
class PairingRequest:
    invite_secret: bytes
    joiner_name: str
    joiner_signing_public: bytes
    joiner_agreement_public: bytes
    joiner_ephemeral_public: bytes
    joiner_ratchet_public: bytes
    joiner_profile: bytes = b""
    kem_ciphertext: bytes = b""

    def to_bytes(self) -> bytes:
        payload: dict[str, bytes | str] = {
            "invite_secret": self.invite_secret,
            "joiner_name": self.joiner_name,
            "joiner_signing_public": self.joiner_signing_public,
            "joiner_agreement_public": self.joiner_agreement_public,
            "joiner_ephemeral_public": self.joiner_ephemeral_public,
            "joiner_ratchet_public": self.joiner_ratchet_public,
            "joiner_profile": self.joiner_profile,
        }
        if self.kem_ciphertext:
            payload["kem_ciphertext"] = self.kem_ciphertext
        return cbor2.dumps(payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingRequest:
        payload = cbor2.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("invalid pairing request")
        return cls(
            invite_secret=bytes(payload["invite_secret"]),
            joiner_name=str(payload["joiner_name"]),
            joiner_signing_public=bytes(payload["joiner_signing_public"]),
            joiner_agreement_public=bytes(payload["joiner_agreement_public"]),
            joiner_ephemeral_public=bytes(payload["joiner_ephemeral_public"]),
            joiner_ratchet_public=bytes(payload.get("joiner_ratchet_public", b"")),
            joiner_profile=bytes(payload.get("joiner_profile", b"")),
            kem_ciphertext=bytes(payload.get("kem_ciphertext", b"")),
        )


@dataclass(frozen=True)
class PairingResponse:
    inviter_ephemeral_public: bytes
    inviter_ratchet_public: bytes
    transcript_hash: bytes
    inviter_profile: bytes = b""

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "inviter_ephemeral_public": self.inviter_ephemeral_public,
                "inviter_ratchet_public": self.inviter_ratchet_public,
                "transcript_hash": self.transcript_hash,
                "inviter_profile": self.inviter_profile,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> PairingResponse:
        payload = cbor2.loads(data)
        if not isinstance(payload, dict):
            raise ValueError("invalid pairing response")
        return cls(
            inviter_ephemeral_public=bytes(payload["inviter_ephemeral_public"]),
            inviter_ratchet_public=bytes(payload.get("inviter_ratchet_public", b"")),
            transcript_hash=bytes(payload["transcript_hash"]),
            inviter_profile=bytes(payload.get("inviter_profile", b"")),
        )


@dataclass(frozen=True)
class PairingSecrets:
    ephemeral_private: x25519.X25519PrivateKey
    ratchet_private: x25519.X25519PrivateKey
    pq_secret: bytes | None = None


def build_pairing_request(
    identity: Identity,
    invite: InviteBundle,
    joiner_name: str,
    *,
    joiner_profile: bytes = b"",
) -> tuple[PairingRequest, PairingSecrets]:
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ratchet_private = x25519.X25519PrivateKey.generate()
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
        joiner_ratchet_public=ratchet_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        joiner_profile=joiner_profile,
        kem_ciphertext=kem_ciphertext,
    )
    return request, PairingSecrets(
        ephemeral_private=ephemeral_private,
        ratchet_private=ratchet_private,
        pq_secret=pq_secret,
    )


def pairing_transcript(
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_public: bytes,
    inviter_ratchet_public: bytes,
) -> bytes:
    validate_pairing_request_for_invite(invite, request)
    parts = [
        invite.protocol.encode("utf-8"),
        invite.invite_secret,
        invite.signing_public,
        invite.agreement_public,
        request.joiner_signing_public,
        request.joiner_agreement_public,
        request.joiner_ephemeral_public,
        inviter_ephemeral_public,
        request.joiner_ratchet_public,
        inviter_ratchet_public,
    ]
    if invite_supports_hybrid(invite):
        parts.append(request.kem_ciphertext)
    return hashlib.sha256(b"|".join(parts)).digest()


def validate_pairing_request_for_invite(
    invite: InviteBundle,
    request: PairingRequest,
) -> None:
    """Reject PQ downgrade (hybrid invite without KEM) and classical uplift."""
    if request.invite_secret != invite.invite_secret:
        raise ValueError("pairing invite secret mismatch")
    if len(request.joiner_ratchet_public) != 32:
        raise ValueError("pairing request missing joiner ratchet public key")
    if invite_supports_hybrid(invite):
        if not request.kem_ciphertext:
            raise ValueError("hybrid invite requires kem ciphertext")
        return
    if request.kem_ciphertext:
        raise ValueError("unexpected kem ciphertext on classical invite")


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


def pair_request_to_url(request: PairingRequest) -> str:
    encoded = b64encode(request.to_bytes())
    return f"{PAIR_REQUEST_PREFIX}{encoded}"


def pair_request_from_url(url: str) -> PairingRequest:
    if not url.startswith(PAIR_REQUEST_PREFIX):
        raise ValueError("invalid pair request url")
    return PairingRequest.from_bytes(b64decode(url[len(PAIR_REQUEST_PREFIX) :]))


def pair_response_to_url(response: PairingResponse) -> str:
    encoded = b64encode(response.to_bytes())
    return f"{PAIR_RESPONSE_PREFIX}{encoded}"


def pair_response_from_url(url: str) -> PairingResponse:
    if not url.startswith(PAIR_RESPONSE_PREFIX):
        raise ValueError("invalid pair response url")
    return PairingResponse.from_bytes(b64decode(url[len(PAIR_RESPONSE_PREFIX) :]))


@dataclass(frozen=True)
class PendingPairingSession:
    invite_url: str
    request_url: str
    ephemeral_private_hex: str
    ratchet_private_hex: str
    pq_secret_hex: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "invite_url": self.invite_url,
            "request_url": self.request_url,
            "ephemeral_private_hex": self.ephemeral_private_hex,
            "ratchet_private_hex": self.ratchet_private_hex,
            "pq_secret_hex": self.pq_secret_hex,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | None]) -> PendingPairingSession:
        ratchet_hex = payload.get("ratchet_private_hex")
        if not ratchet_hex:
            raise ValueError("pending pairing session missing ratchet private key")
        return cls(
            invite_url=str(payload["invite_url"]),
            request_url=str(payload["request_url"]),
            ephemeral_private_hex=str(payload["ephemeral_private_hex"]),
            ratchet_private_hex=str(ratchet_hex),
            pq_secret_hex=payload.get("pq_secret_hex"),
        )

    def secrets(self) -> PairingSecrets:
        private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(self.ephemeral_private_hex))
        ratchet_private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(self.ratchet_private_hex))
        pq_secret = bytes.fromhex(self.pq_secret_hex) if self.pq_secret_hex else None
        return PairingSecrets(
            ephemeral_private=private,
            ratchet_private=ratchet_private,
            pq_secret=pq_secret,
        )


def _ephemeral_private_hex(key: x25519.X25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()


def build_offline_pairing_request(
    identity: Identity,
    invite: InviteBundle,
    *,
    joiner_name: str | None = None,
    joiner_profile: bytes = b"",
) -> tuple[PairingRequest, PairingSecrets, str]:
    request, secrets = build_pairing_request(
        identity,
        invite,
        joiner_name=joiner_name or identity.name,
        joiner_profile=joiner_profile,
    )
    return request, secrets, pair_request_to_url(request)


def respond_to_pair_request(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    *,
    inviter_profile: bytes = b"",
    inviter_ephemeral_private: x25519.X25519PrivateKey | None = None,
    inviter_ratchet_private: x25519.X25519PrivateKey | None = None,
) -> tuple[PairingResponse, Contact, str]:
    from yakr_core.invite import verify_invite

    verify_invite(invite)
    if request.invite_secret != invite.invite_secret:
        raise ValueError("pairing request invite secret mismatch")
    ephemeral = inviter_ephemeral_private or x25519.X25519PrivateKey.generate()
    response, contact = inviter_complete_pairing(
        identity,
        invite,
        request,
        ephemeral,
        inviter_profile=inviter_profile,
        inviter_ratchet_private=inviter_ratchet_private,
    )
    return response, contact, pair_response_to_url(response)


def finish_offline_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    secrets: PairingSecrets,
    response_url: str,
    *,
    contact_name: str | None = None,
) -> Contact:
    response = pair_response_from_url(response_url)
    contact = joiner_complete_pairing(identity, invite, request, secrets, response)
    contact.name = contact_name or invite.inviter_name
    return contact


def pending_session_from_request(
    invite_url: str,
    request: PairingRequest,
    secrets: PairingSecrets,
) -> PendingPairingSession:
    pq_hex = secrets.pq_secret.hex() if secrets.pq_secret else None
    return PendingPairingSession(
        invite_url=invite_url,
        request_url=pair_request_to_url(request),
        ephemeral_private_hex=_ephemeral_private_hex(secrets.ephemeral_private),
        ratchet_private_hex=_ephemeral_private_hex(secrets.ratchet_private),
        pq_secret_hex=pq_hex,
    )


def inviter_complete_pairing(
    identity: Identity,
    invite: InviteBundle,
    request: PairingRequest,
    inviter_ephemeral_private: x25519.X25519PrivateKey,
    *,
    inviter_profile: bytes = b"",
    inviter_ratchet_private: x25519.X25519PrivateKey | None = None,
) -> tuple[PairingResponse, Contact]:
    validate_pairing_request_for_invite(invite, request)
    inviter_ephemeral_public = inviter_ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    inviter_ratchet_private = inviter_ratchet_private or x25519.X25519PrivateKey.generate()
    inviter_ratchet_public = inviter_ratchet_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    transcript_hash = pairing_transcript(
        invite,
        request,
        inviter_ephemeral_public,
        inviter_ratchet_public,
    )
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
    ratchet = RatchetState.from_master(
        master,
        is_initiator=True,
        hybrid=hybrid,
        ratchet_private=inviter_ratchet_private,
    )
    ratchet.pending_pairing_dh_ratchet_peer = request.joiner_ratchet_public
    now = int(time.time() * 1000)
    contact = Contact(
        name=request.joiner_name,
        signing_public=request.joiner_signing_public,
        agreement_public=request.joiner_agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(identity.name, request.joiner_name),
        contact_id=contact_id_for(request.joiner_signing_public, request.joiner_agreement_public),
        transcript_hash=transcript_hash,
        ratchet=ratchet,
        delivery_profile=profile_from_pairing_bytes(
            request.joiner_profile,
            request.joiner_signing_public,
        ),
        hybrid_pq=hybrid,
        session_started_at=now,
    )
    apply_peer_profile_ack_from_bytes(contact, inviter_profile, identity.signing_public_bytes)
    response = PairingResponse(
        inviter_ephemeral_public=inviter_ephemeral_public,
        inviter_ratchet_public=inviter_ratchet_public,
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
    if response.transcript_hash != pairing_transcript(
        invite,
        request,
        response.inviter_ephemeral_public,
        response.inviter_ratchet_public,
    ):
        raise ValueError("pairing transcript mismatch")
    if len(response.inviter_ratchet_public) != 32:
        raise ValueError("pairing response missing inviter ratchet public key")
    validate_pairing_request_for_invite(invite, request)
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
    ratchet = RatchetState.from_master(
        master,
        is_initiator=False,
        hybrid=hybrid,
        ratchet_private=secrets.ratchet_private,
    )
    ratchet._pairing_recv_init(response.inviter_ratchet_public)
    contact = Contact(
        name=invite.inviter_name,
        signing_public=invite.signing_public,
        agreement_public=invite.agreement_public,
        master_secret=master,
        conversation_id=conversation_id_for(invite.inviter_name, identity.name),
        contact_id=contact_id_for(invite.signing_public, invite.agreement_public),
        transcript_hash=response.transcript_hash,
        ratchet=ratchet,
        delivery_profile=profile_from_pairing_bytes(
            response.inviter_profile,
            invite.signing_public,
        ),
        hybrid_pq=hybrid,
        session_started_at=now,
    )
    apply_peer_profile_ack_from_bytes(contact, request.joiner_profile, identity.signing_public_bytes)
    return contact
