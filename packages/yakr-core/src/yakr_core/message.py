from __future__ import annotations

import base64
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Literal


MessageType = Literal["text", "receipt"]


@dataclass
class InnerMessage:
    version: int
    conversation_id: str
    sender_device_id: str
    seq: int
    created_at: int
    type: MessageType
    body: str = ""
    message_id: str | None = None

    def to_bytes(self) -> bytes:
        payload = asdict(self)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> InnerMessage:
        payload: dict[str, Any] = json.loads(data.decode("utf-8"))
        return cls(
            version=int(payload["version"]),
            conversation_id=str(payload["conversation_id"]),
            sender_device_id=str(payload["sender_device_id"]),
            seq=int(payload["seq"]),
            created_at=int(payload["created_at"]),
            type=payload["type"],
            body=str(payload.get("body", "")),
            message_id=payload.get("message_id"),
        )

    @classmethod
    def text(
        cls,
        *,
        conversation_id: str,
        sender_device_id: str,
        seq: int,
        body: str,
    ) -> InnerMessage:
        return cls(
            version=1,
            conversation_id=conversation_id,
            sender_device_id=sender_device_id,
            seq=seq,
            created_at=int(time.time() * 1000),
            type="text",
            body=body,
        )

    @classmethod
    def receipt(
        cls,
        *,
        conversation_id: str,
        sender_device_id: str,
        seq: int,
        message_id: str,
    ) -> InnerMessage:
        return cls(
            version=1,
            conversation_id=conversation_id,
            sender_device_id=sender_device_id,
            seq=seq,
            created_at=int(time.time() * 1000),
            type="receipt",
            message_id=message_id,
        )


@dataclass(frozen=True)
class OuterBlob:
    version: int
    mailbox_tag: bytes
    expires_at: int
    ciphertext: bytes

    def to_relay_json(self) -> dict[str, Any]:
        return {
            "mailbox_tag": base64.urlsafe_b64encode(self.mailbox_tag).decode("ascii").rstrip("="),
            "expires_at": self.expires_at,
            "ciphertext": base64.urlsafe_b64encode(self.ciphertext).decode("ascii").rstrip("="),
        }

    @classmethod
    def from_relay_json(cls, payload: dict[str, Any]) -> OuterBlob:
        return cls(
            version=1,
            mailbox_tag=_b64decode(str(payload["mailbox_tag"])),
            expires_at=int(payload["expires_at"]),
            ciphertext=_b64decode(str(payload["ciphertext"])),
        )


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def message_id(ciphertext: bytes) -> str:
    digest = hashlib_sha256(b"yakr/v0.1/message-id|" + ciphertext)
    return digest.hex()


def hashlib_sha256(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(data).digest()
