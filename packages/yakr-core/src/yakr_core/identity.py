from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from yakr_core.crypto import derive_master_secret, x25519_shared_secret

if TYPE_CHECKING:
    from yakr_core.ratchet import RatchetState


@dataclass
class Identity:
    name: str
    signing_private: ed25519.Ed25519PrivateKey
    agreement_private: x25519.X25519PrivateKey

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
    def generate(cls, name: str) -> Identity:
        return cls(
            name=name,
            signing_private=ed25519.Ed25519PrivateKey.generate(),
            agreement_private=x25519.X25519PrivateKey.generate(),
        )

    def to_dict(self) -> dict[str, str]:
        return {
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

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> Identity:
        signing_private = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode(payload["signing_private"]))
        agreement_private = x25519.X25519PrivateKey.from_private_bytes(b64decode(payload["agreement_private"]))
        return cls(name=payload["name"], signing_private=signing_private, agreement_private=agreement_private)

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

    @classmethod
    def establish(cls, local: Identity, remote_name: str, remote_bundle: dict[str, str]) -> Contact:
        remote_signing = b64decode(remote_bundle["signing_public"])
        remote_agreement = b64decode(remote_bundle["agreement_public"])
        shared = x25519_shared_secret(local.agreement_private, remote_agreement)
        master = derive_master_secret(shared)
        conversation_id = conversation_id_for(local.name, remote_name)
        return cls(
            name=remote_name,
            signing_public=remote_signing,
            agreement_public=remote_agreement,
            master_secret=master,
            conversation_id=conversation_id,
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
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, str | int]) -> Contact:
        from yakr_core.ratchet import RatchetState

        ratchet = None
        if "ratchet" in payload:
            ratchet = RatchetState.from_dict(json.loads(str(payload["ratchet"])))
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
