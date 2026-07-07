from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Literal

import cbor2
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_core.identity import Identity, b64decode, b64encode
from yakr_core.relay import RelayNode

PROTOCOL_V5 = "yakr-v0.5"
DEFAULT_PROFILE_TTL_MS = 7 * 24 * 60 * 60 * 1000
ReceiptPolicy = Literal["minimal", "none"]


@dataclass(frozen=True)
class RelayDescriptor:
    name: str
    role: str
    url: str
    wrap_secret: bytes

    def to_dict(self) -> dict[str, str | bytes]:
        return {
            "name": self.name,
            "role": self.role,
            "url": self.url,
            "wrap_secret": self.wrap_secret,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | bytes]) -> RelayDescriptor:
        return cls(
            name=str(payload["name"]),
            role=str(payload["role"]),
            url=str(payload["url"]).rstrip("/"),
            wrap_secret=bytes(payload["wrap_secret"]),
        )

    def to_relay_node(self) -> RelayNode:
        return RelayNode(
            name=self.name,
            role=self.role,  # type: ignore[arg-type]
            url=self.url,
            wrap_secret=self.wrap_secret,
        )


@dataclass(frozen=True)
class DeliveryProfile:
    protocol: str
    version: int
    valid_from: int
    valid_until: int
    direct_hints: tuple[str, ...]
    relay_descriptors: tuple[RelayDescriptor, ...]
    mailbox_epoch_secs: int
    mailbox_direction_salt: bytes
    blob_classes: tuple[int, ...]
    receipt_policy: ReceiptPolicy
    signature: bytes

    def unsigned_payload(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": self.protocol,
                "version": self.version,
                "valid_from": self.valid_from,
                "valid_until": self.valid_until,
                "direct_hints": list(self.direct_hints),
                "relay_descriptors": [item.to_dict() for item in self.relay_descriptors],
                "mailbox_params": {
                    "epoch_secs": self.mailbox_epoch_secs,
                    "direction_salt": self.mailbox_direction_salt,
                },
                "blob_classes": list(self.blob_classes),
                "receipt_policy": self.receipt_policy,
            }
        )

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "protocol": self.protocol,
                "version": self.version,
                "valid_from": self.valid_from,
                "valid_until": self.valid_until,
                "direct_hints": list(self.direct_hints),
                "relay_descriptors": [item.to_dict() for item in self.relay_descriptors],
                "mailbox_params": {
                    "epoch_secs": self.mailbox_epoch_secs,
                    "direction_salt": self.mailbox_direction_salt,
                },
                "blob_classes": list(self.blob_classes),
                "receipt_policy": self.receipt_policy,
                "signature": self.signature,
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> DeliveryProfile:
        payload = cbor2.loads(data)
        mailbox_params = payload["mailbox_params"]
        return cls(
            protocol=str(payload["protocol"]),
            version=int(payload["version"]),
            valid_from=int(payload["valid_from"]),
            valid_until=int(payload["valid_until"]),
            direct_hints=tuple(str(item) for item in payload["direct_hints"]),
            relay_descriptors=tuple(
                RelayDescriptor.from_dict(item) for item in payload["relay_descriptors"]
            ),
            mailbox_epoch_secs=int(mailbox_params["epoch_secs"]),
            mailbox_direction_salt=bytes(mailbox_params["direction_salt"]),
            blob_classes=tuple(int(item) for item in payload["blob_classes"]),
            receipt_policy=str(payload["receipt_policy"]),  # type: ignore[assignment]
            signature=bytes(payload["signature"]),
        )

    def to_b64(self) -> str:
        return b64encode(self.to_bytes())

    @classmethod
    def from_b64(cls, value: str) -> DeliveryProfile:
        return cls.from_bytes(b64decode(value))


def create_delivery_profile(
    identity: Identity,
    *,
    relay_descriptors: list[RelayDescriptor],
    direct_hints: list[str] | None = None,
    mailbox_epoch_secs: int = 3600,
    mailbox_direction_salt: bytes | None = None,
    blob_classes: list[int] | None = None,
    receipt_policy: ReceiptPolicy = "minimal",
    ttl_ms: int = DEFAULT_PROFILE_TTL_MS,
    version: int | None = None,
) -> DeliveryProfile:
    now = int(time.time() * 1000)
    if not relay_descriptors:
        raise ValueError("delivery profile requires at least one relay descriptor")
    unsigned = {
        "protocol": PROTOCOL_V5,
        "version": (version or 1),
        "valid_from": now,
        "valid_until": now + ttl_ms,
        "direct_hints": direct_hints or [],
        "relay_descriptors": [item.to_dict() for item in relay_descriptors],
        "mailbox_params": {
            "epoch_secs": mailbox_epoch_secs,
            "direction_salt": mailbox_direction_salt or b"",
        },
        "blob_classes": blob_classes or [4096],
        "receipt_policy": receipt_policy,
    }
    payload = cbor2.dumps(unsigned)
    signature = identity.signing_private.sign(payload)
    return DeliveryProfile(
        protocol=unsigned["protocol"],
        version=unsigned["version"],
        valid_from=unsigned["valid_from"],
        valid_until=unsigned["valid_until"],
        direct_hints=tuple(unsigned["direct_hints"]),
        relay_descriptors=tuple(relay_descriptors),
        mailbox_epoch_secs=mailbox_epoch_secs,
        mailbox_direction_salt=mailbox_direction_salt or b"",
        blob_classes=tuple(unsigned["blob_classes"]),
        receipt_policy=receipt_policy,
        signature=bytes(signature),
    )


def verify_delivery_profile(profile: DeliveryProfile, signing_public: bytes) -> None:
    if profile.protocol != PROTOCOL_V5:
        raise ValueError("unsupported delivery profile protocol")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(signing_public)
    public_key.verify(profile.signature, profile.unsigned_payload())


def profile_is_expired(profile: DeliveryProfile, *, now_ms: int | None = None) -> bool:
    now = int(time.time() * 1000) if now_ms is None else now_ms
    return profile.valid_until < now


def profile_is_stale(profile: DeliveryProfile, *, now_ms: int | None = None) -> bool:
    """A profile is stale once it is past valid_until."""
    return profile_is_expired(profile, now_ms=now_ms)


def relay_network_from_profile(profile: DeliveryProfile) -> dict[str, RelayNode]:
    return {descriptor.name: descriptor.to_relay_node() for descriptor in profile.relay_descriptors}


def mailbox_descriptors(profile: DeliveryProfile) -> list[RelayDescriptor]:
    return [item for item in profile.relay_descriptors if item.role in ("mailbox", "both")]


def entry_descriptors(profile: DeliveryProfile) -> list[RelayDescriptor]:
    return [item for item in profile.relay_descriptors if item.role in ("entry", "both")]
