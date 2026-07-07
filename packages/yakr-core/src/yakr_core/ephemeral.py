from __future__ import annotations

import time

# Non-negotiable message lifetime for text and receipts (24 hours).
MESSAGE_TTL_MS = 24 * 60 * 60 * 1000
# Ephemeral relay reachability hints (presence).
PRESENCE_TTL_MS = 30 * 60 * 1000
DEFAULT_BLOB_TTL_MS = MESSAGE_TTL_MS
MAX_RELAY_BLOB_TTL_MS = MESSAGE_TTL_MS


def message_valid_until(*, created_at_ms: int | None = None) -> int:
    created = created_at_ms if created_at_ms is not None else int(time.time() * 1000)
    return created + MESSAGE_TTL_MS


def is_message_expired(valid_until_ms: int, *, now_ms: int | None = None) -> bool:
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    return now > valid_until_ms


def enforce_message_ttl(valid_until_ms: int, *, now_ms: int | None = None) -> None:
    from yakr_core.errors import MessageExpiredError

    if is_message_expired(valid_until_ms, now_ms=now_ms):
        raise MessageExpiredError("message TTL expired")
