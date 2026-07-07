from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

from yakr_core.crypto import derive_master_secret, x25519_shared_secret


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
            "signing_private": _b64(self.signing_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
            "agreement_private": _b64(self.agreement_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> Identity:
        signing_private = ed25519.Ed25519PrivateKey.from_private_bytes(_db64(payload["signing_private"]))
        agreement_private = x25519.X25519PrivateKey.from_private_bytes(_db64(payload["agreement_private"]))
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

    @classmethod
    def establish(cls, local: Identity, remote_name: str, remote_bundle: dict[str, str]) -> Contact:
        remote_signing = _db64(remote_bundle["signing_public"])
        remote_agreement = _db64(remote_bundle["agreement_public"])
        shared = x25519_shared_secret(local.agreement_private, remote_agreement)
        master = derive_master_secret(shared)
        conversation_id = _conversation_id(local.name, remote_name)
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
            "signing_public": _b64(self.signing_public),
            "agreement_public": _b64(self.agreement_public),
        }

    def to_dict(self) -> dict[str, str | int]:
        return {
            "name": self.name,
            "signing_public": _b64(self.signing_public),
            "agreement_public": _b64(self.agreement_public),
            "master_secret": _b64(self.master_secret),
            "conversation_id": self.conversation_id,
            "next_send_seq": self.next_send_seq,
            "last_recv_seq": self.last_recv_seq,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | int]) -> Contact:
        return cls(
            name=str(payload["name"]),
            signing_public=_db64(str(payload["signing_public"])),
            agreement_public=_db64(str(payload["agreement_public"])),
            master_secret=_db64(str(payload["master_secret"])),
            conversation_id=str(payload["conversation_id"]),
            next_send_seq=int(payload.get("next_send_seq", 1)),
            last_recv_seq=int(payload.get("last_recv_seq", 0)),
        )


def export_public_bundle(identity: Identity) -> dict[str, str]:
    return {
        "name": identity.name,
        "signing_public": _b64(identity.signing_public_bytes),
        "agreement_public": _b64(identity.agreement_public_bytes),
    }


def _conversation_id(a: str, b: str) -> str:
    left, right = sorted([a, b])
    return f"pairwise_{left}_{right}"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _db64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
