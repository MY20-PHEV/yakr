from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

from yakr_core.ephemeral import PRESENCE_TTL_MS
from yakr_core.errors import YakrError
from yakr_core.identity import Contact
from yakr_core.message import InnerMessage
from yakr_core.store import FileLocalStore

PRESENCE_PROTOCOL = "yakr-v1.1/presence"


@dataclass(frozen=True)
class PresencePayload:
    """Ephemeral relay reachability for a paired operator (location, not identity)."""

    operator_name: str
    reachable_url: str
    relay_active: bool
    valid_until: int
    protocol: str = PRESENCE_PROTOCOL

    def to_bytes(self) -> bytes:
        return json.dumps(
            {
                "protocol": self.protocol,
                "operator_name": self.operator_name,
                "reachable_url": self.reachable_url.rstrip("/"),
                "relay_active": self.relay_active,
                "valid_until": self.valid_until,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> PresencePayload:
        payload: dict[str, Any] = json.loads(data.decode("utf-8"))
        if payload.get("protocol") != PRESENCE_PROTOCOL:
            raise ValueError("unsupported presence protocol")
        return cls(
            operator_name=str(payload["operator_name"]),
            reachable_url=str(payload["reachable_url"]).rstrip("/"),
            relay_active=bool(payload["relay_active"]),
            valid_until=int(payload["valid_until"]),
        )

    def to_b64(self) -> str:
        return base64.urlsafe_b64encode(self.to_bytes()).decode("ascii").rstrip("=")

    @classmethod
    def from_b64(cls, value: str) -> PresencePayload:
        padding = "=" * (-len(value) % 4)
        return cls.from_bytes(base64.urlsafe_b64decode(value + padding))

    @classmethod
    def for_operator(
        cls,
        operator_name: str,
        reachable_url: str,
        *,
        relay_active: bool = True,
        created_at_ms: int | None = None,
    ) -> PresencePayload:
        now = created_at_ms if created_at_ms is not None else int(time.time() * 1000)
        return cls(
            operator_name=operator_name,
            reachable_url=reachable_url.rstrip("/"),
            relay_active=relay_active,
            valid_until=now + PRESENCE_TTL_MS,
        )


def presence_valid_until(*, created_at_ms: int | None = None) -> int:
    now = created_at_ms if created_at_ms is not None else int(time.time() * 1000)
    return now + PRESENCE_TTL_MS


def is_presence_fresh(payload: PresencePayload, *, now_ms: int | None = None) -> bool:
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    return payload.relay_active and payload.valid_until > now


def apply_presence_message(
    store: FileLocalStore,
    contact: Contact,
    inner: InnerMessage,
) -> PresencePayload | None:
    """Validate and cache presence from a paired operator contact."""
    if inner.type != "presence":
        return None
    payload = PresencePayload.from_b64(inner.body)
    if payload.operator_name != contact.name:
        raise YakrError(
            f"presence operator {payload.operator_name!r} does not match contact {contact.name!r}",
            code="YAKR_ERR_PRESENCE_INVALID",
        )
    if not is_presence_fresh(payload):
        return None
    store.save_presence(payload, source_contact=contact.name)
    return payload


def resolve_operator_url(
    store: FileLocalStore | None,
    operator_name: str,
    profile_url: str,
    *,
    now_ms: int | None = None,
) -> str:
    """Prefer fresh presence location over signed profile URL."""
    if store is None:
        return profile_url.rstrip("/")
    cached = store.load_presence(operator_name)
    if cached is not None and is_presence_fresh(cached, now_ms=now_ms):
        return cached.reachable_url.rstrip("/")
    return profile_url.rstrip("/")
