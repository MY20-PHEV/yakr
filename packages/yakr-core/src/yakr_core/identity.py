from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, ec, x25519

from yakr_core.crypto import derive_master_secret, derive_mailbox_secret, x25519_shared_secret
from yakr_core.ratchet import RatchetState
from yakr_core.hybrid_pq import kem_generate_keypair

if TYPE_CHECKING:
    from yakr_core.delivery_profile import DeliveryProfile
    from yakr_core.privacy import PrivacyMode
    from yakr_core.ratchet import RatchetState


@dataclass
class Identity:
    name: str
    signing_private: ed25519.Ed25519PrivateKey
    agreement_private: x25519.X25519PrivateKey
    kem_public: bytes = b""
    kem_private: bytes = b""
    pq_signing_public: bytes = b""
    pq_signing_private: bytes = b""
    tls_ecdsa_private: ec.EllipticCurvePrivateKey | None = None

    @property
    def device_id(self) -> str:
        pub = self.signing_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return pub.hex()[:16]

    @property
    def signing_public_bytes(self) -> bytes:
        return self.signing_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def agreement_public_bytes(self) -> bytes:
        return self.agreement_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def generate(cls, name: str, *, hybrid_pq: bool = True) -> Identity:
        kem_public, kem_private = kem_generate_keypair() if hybrid_pq else (b"", b"")
        pq_signing_public = b""
        pq_signing_private = b""
        if hybrid_pq:
            from pqcrypto.sign.ml_dsa_65 import generate_keypair as pq_generate_keypair

            pq_signing_public, pq_signing_private = pq_generate_keypair()
        return cls(
            name=name,
            signing_private=ed25519.Ed25519PrivateKey.generate(),
            agreement_private=x25519.X25519PrivateKey.generate(),
            kem_public=kem_public,
            kem_private=kem_private,
            pq_signing_public=pq_signing_public,
            pq_signing_private=pq_signing_private,
            tls_ecdsa_private=ec.generate_private_key(ec.SECP256R1()),
        )

    def to_dict(self) -> dict[str, str]:
        payload = {
            "name": self.name,
            "signing_private": b64encode(self.signing_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
            "agreement_private": b64encode(self.agreement_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
        }
        if self.kem_private:
            payload["kem_public"] = b64encode(self.kem_public)
            payload["kem_private"] = b64encode(self.kem_private)
        if self.pq_signing_private:
            payload["pq_signing_public"] = b64encode(self.pq_signing_public)
            payload["pq_signing_private"] = b64encode(self.pq_signing_private)
        if self.tls_ecdsa_private is not None:
            payload["tls_ecdsa_private"] = b64encode(
                self.tls_ecdsa_private.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> Identity:
        signing_private = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(payload["signing_private"]))
        agreement_private = x25519.X25519PrivateKey.from_private_bytes(b64decode(payload["agreement_private"]))
        tls_ecdsa_private = None
        if "tls_ecdsa_private" in payload:
            tls_ecdsa_private = serialization.load_der_private_key(
                b64decode(payload["tls_ecdsa_private"]),
                password=None,
            )
        return cls(
            name=payload["name"],
            signing_private=signing_private,
            agreement_private=agreement_private,
            kem_public=b64decode(payload["kem_public"]) if "kem_public" in payload else b"",
            kem_private=b64decode(payload["kem_private"]) if "kem_private" in payload else b"",
            pq_signing_public=b64decode(payload["pq_signing_public"]) if "pq_signing_public" in payload else b"",
            pq_signing_private=b64decode(payload["pq_signing_private"]) if "pq_signing_private" in payload else b"",
            tls_ecdsa_private=tls_ecdsa_private,  # type: ignore[arg-type]
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Identity:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(payload)


@dataclass
class Contact:
    name: str
    signing_public: bytes
    agreement_public: bytes
    master_secret: bytes
    conversation_id: str
    next_send_seq: int = 1
    last_recv_seq: int = 0
    contact_id: bytes | None = None
    transcript_hash: bytes | None = None
    ratchet: RatchetState | None = None
    delivery_profile: DeliveryProfile | None = None
    hybrid_pq: bool = False
    session_started_at: int = 0
    privacy_mode: PrivacyMode = "fast"

    @classmethod
    def establish(cls, local: Identity, remote_name: str, remote_bundle: dict[str, str]) -> Contact:
        remote_signing = b64decode(remote_bundle["signing_public"])
        remote_agreement = b64decode(remote_bundle["agreement_public"])
        shared = x25519_shared_secret(local.agreement_private, remote_agreement)
        master = derive_master_secret(shared)
        conversation_id = conversation_id_for(local.name, remote_name)
        is_initiator = local.name < remote_name
        return cls(
            name=remote_name,
            signing_public=remote_signing,
            agreement_public=remote_agreement,
            master_secret=master,
            conversation_id=conversation_id,
            ratchet=RatchetState.from_master(master, is_initiator=is_initiator),
        )

    def public_bundle(self) -> dict[str, str]:
        return {
            "name": self.name,
            "signing_public": b64encode(self.signing_public),
            "agreement_public": b64encode(self.agreement_public),
        }

    def to_dict(self) -> dict[str, str | int]:
        payload: dict[str, str | int] = {
            "name": self.name,
            "signing_public": b64encode(self.signing_public),
            "agreement_public": b64encode(self.agreement_public),
            "master_secret": b64encode(self.master_secret),
            "conversation_id": self.conversation_id,
            "next_send_seq": self.next_send_seq,
            "last_recv_seq": self.last_recv_seq,
        }
        if self.contact_id is not None:
            payload["contact_id"] = b64encode(self.contact_id)
        if self.transcript_hash is not None:
            payload["transcript_hash"] = b64encode(self.transcript_hash)
        if self.ratchet is not None:
            payload["ratchet"] = json.dumps(self.ratchet.to_dict())
        if self.delivery_profile is not None:
            payload["delivery_profile"] = self.delivery_profile.to_b64()
        if self.hybrid_pq:
            payload["hybrid_pq"] = 1
        if self.session_started_at:
            payload["session_started_at"] = self.session_started_at
        if self.privacy_mode != "fast":
            payload["privacy_mode"] = self.privacy_mode
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, str | int]) -> Contact:
        from yakr_core.delivery_profile import DeliveryProfile
        from yakr_core.ratchet import RatchetState

        ratchet = None
        if "ratchet" in payload:
            ratchet = RatchetState.from_dict(json.loads(str(payload["ratchet"])))
        delivery_profile = None
        if "delivery_profile" in payload:
            delivery_profile = DeliveryProfile.from_b64(str(payload["delivery_profile"]))
        contact_id = b64decode(str(payload["contact_id"])) if "contact_id" in payload else None
        transcript_hash = (
            b64decode(str(payload["transcript_hash"])) if "transcript_hash" in payload else None
        )
        return cls(
            name=str(payload["name"]),
            signing_public=b64decode(str(payload["signing_public"])),
            agreement_public=b64decode(str(payload["agreement_public"])),
            master_secret=b64decode(str(payload["master_secret"])),
            conversation_id=str(payload["conversation_id"]),
            next_send_seq=int(payload.get("next_send_seq", 1)),
            last_recv_seq=int(payload.get("last_recv_seq", 0)),
            contact_id=contact_id,
            transcript_hash=transcript_hash,
            ratchet=ratchet,
            delivery_profile=delivery_profile,
            hybrid_pq=bool(int(payload.get("hybrid_pq", 0))),
            session_started_at=int(payload.get("session_started_at", 0)),
            privacy_mode=str(payload.get("privacy_mode", "fast")),  # type: ignore[arg-type]
        )


def export_public_bundle(identity: Identity) -> dict[str, str]:
    return {
        "name": identity.name,
        "signing_public": b64encode(identity.signing_public_bytes),
        "agreement_public": b64encode(identity.agreement_public_bytes),
    }


def conversation_id_for(a: str, b: str) -> str:
    left, right = sorted([a, b])
    return f"pairwise_{left}_{right}"


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# Backward-compatible aliases used by older modules.
_b64 = b64encode
_db64 = b64decode
_conversation_id = conversation_id_for
