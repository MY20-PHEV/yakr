from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from typing import Literal

from yakr_core.crypto import hkdf_derive
from yakr_core.mailbox import MailboxTag, MailboxTagDeriver

PrivacyMode = Literal["fast", "balanced", "high"]
PROTOCOL_V7 = "yakr-v0.7"

SIZE_4K = 4096
SIZE_32K = 32768
BALANCED_DECOY_COUNT = 3
HIGH_DECOY_COUNT = 7


@dataclass(frozen=True)
class PrivacyConfig:
    mode: PrivacyMode = "fast"
    relay_delay_max_secs: int = 0

    @classmethod
    def for_mode(cls, mode: PrivacyMode) -> PrivacyConfig:
        if mode == "balanced":
            return cls(mode=mode, relay_delay_max_secs=15)
        if mode == "high":
            return cls(mode=mode, relay_delay_max_secs=90)
        return cls(mode=mode, relay_delay_max_secs=0)


def size_classes(mode: PrivacyMode) -> list[int]:
    if mode == "high":
        return [SIZE_4K, SIZE_32K]
    if mode == "balanced":
        return [SIZE_4K]
    return []


def select_size_class(plaintext_len: int, mode: PrivacyMode) -> int | None:
    if mode == "fast":
        return None
    classes = size_classes(mode)
    needed = plaintext_len + 4
    for class_size in sorted(classes):
        if needed <= class_size:
            return class_size
    return max(classes)


def pad_plaintext(plaintext: bytes, mode: PrivacyMode) -> tuple[bytes, int]:
    """Pad plaintext to a privacy size class. Returns (padded, padding_bytes)."""
    class_size = select_size_class(len(plaintext), mode)
    if class_size is None:
        return plaintext, 0
    framed = len(plaintext).to_bytes(4, "big") + plaintext
    if len(framed) > class_size:
        raise ValueError("plaintext exceeds maximum size class")
    padded = framed + b"\x00" * (class_size - len(framed))
    return padded, class_size - len(plaintext)


def unpad_plaintext(padded: bytes) -> bytes:
    if len(padded) < 4:
        raise ValueError("padded payload too short")
    length = int.from_bytes(padded[:4], "big")
    end = 4 + length
    if end > len(padded):
        raise ValueError("invalid padded length prefix")
    return padded[4:end]


def decode_padded_plaintext(data: bytes, mode: PrivacyMode) -> bytes:
    if mode == "fast":
        return data
    return unpad_plaintext(data)


def ciphertext_length_for_body(body: str, mode: PrivacyMode, *, inner_overhead: int = 200) -> int:
    """Estimate AEAD ciphertext length after padding (nonce + ciphertext + tag)."""
    raw = json.dumps({"body": body}).encode("utf-8")
    padded, _ = pad_plaintext(raw, mode)
    return 24 + len(padded) + 16


def decoy_count(mode: PrivacyMode) -> int:
    if mode == "balanced":
        return BALANCED_DECOY_COUNT
    if mode == "high":
        return HIGH_DECOY_COUNT
    return 0


def derive_decoy_tag(
    *,
    mailbox_secret: bytes,
    direction: str,
    epoch: int,
    index: int,
) -> MailboxTag:
    material = f"decoy|{direction}|{epoch}|{index}".encode("utf-8")
    tag = hmac.new(mailbox_secret, material, hashlib.sha256).digest()
    return MailboxTag(tag=tag, epoch=epoch, direction=direction)


def fetch_tags_for_mode(
    deriver: MailboxTagDeriver,
    direction: str,
    mode: PrivacyMode,
    *,
    mailbox_secret: bytes,
    lookback: int = 2,
) -> list[MailboxTag]:
    real_tags = deriver.candidate_epochs(direction, lookback=lookback)
    if mode == "fast":
        return real_tags

    tags = list(real_tags)
    for real in real_tags:
        for index in range(decoy_count(mode)):
            tags.append(
                derive_decoy_tag(
                    mailbox_secret=mailbox_secret,
                    direction=direction,
                    epoch=real.epoch,
                    index=index,
                )
            )
    return tags


def generate_dummy_ciphertext(*, size_class: int) -> bytes:
    """Random ciphertext sized to a privacy class for high-mode dummy traffic."""
    payload = secrets.token_bytes(max(0, size_class - 40))
    return secrets.token_bytes(24) + payload + secrets.token_bytes(16)


@dataclass
class PrivacyMetrics:
    bytes_sent: int = 0
    bytes_fetched: int = 0
    decoy_fetches: int = 0
    padding_bytes: int = 0
    dummy_blobs_sent: int = 0
    send_count: int = 0
    fetch_count: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "bytes_sent": self.bytes_sent,
            "bytes_fetched": self.bytes_fetched,
            "decoy_fetches": self.decoy_fetches,
            "padding_bytes": self.padding_bytes,
            "dummy_blobs_sent": self.dummy_blobs_sent,
            "send_count": self.send_count,
            "fetch_count": self.fetch_count,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, int]) -> PrivacyMetrics:
        return cls(
            bytes_sent=int(payload.get("bytes_sent", 0)),
            bytes_fetched=int(payload.get("bytes_fetched", 0)),
            decoy_fetches=int(payload.get("decoy_fetches", 0)),
            padding_bytes=int(payload.get("padding_bytes", 0)),
            dummy_blobs_sent=int(payload.get("dummy_blobs_sent", 0)),
            send_count=int(payload.get("send_count", 0)),
            fetch_count=int(payload.get("fetch_count", 0)),
        )

    def record_send(self, ciphertext_len: int, *, padding_bytes: int = 0) -> None:
        self.bytes_sent += ciphertext_len
        self.padding_bytes += padding_bytes
        self.send_count += 1

    def record_fetch(self, bytes_fetched: int, *, decoy: bool = False) -> None:
        self.bytes_fetched += bytes_fetched
        self.fetch_count += 1
        if decoy:
            self.decoy_fetches += 1


def relay_delay_secs(mode: PrivacyMode, *, seed: bytes | None = None) -> float:
    config = PrivacyConfig.for_mode(mode)
    if config.relay_delay_max_secs <= 0:
        return 0.0
    if mode == "high":
        minimum = 5
    else:
        minimum = 0
    maximum = config.relay_delay_max_secs
    if seed is not None:
        pick = int.from_bytes(hkdf_derive(seed, b"yakr/v0.7/relay-delay")[:4], "big")
        fraction = pick / 0xFFFFFFFF
    else:
        fraction = secrets.randbelow(10_000) / 10_000.0
    return minimum + fraction * (maximum - minimum)
