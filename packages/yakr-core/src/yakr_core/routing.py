from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from yakr_core.crypto import hkdf_derive
from yakr_core.relay import RelayNode


@dataclass
class RouteState:
    last_entry: str | None = None
    last_mailbox: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {"last_entry": self.last_entry, "last_mailbox": self.last_mailbox}

    @classmethod
    def from_dict(cls, payload: dict[str, str | None]) -> RouteState:
        return cls(
            last_entry=payload.get("last_entry"),
            last_mailbox=payload.get("last_mailbox"),
        )


def _weighted_score(
    *,
    entry: RelayNode,
    mailbox: RelayNode,
    state: RouteState,
) -> float:
    score = 1.0
    if entry.name == state.last_entry:
        score *= 0.05
    if mailbox.name == state.last_mailbox:
        score *= 0.05
    if entry.name == mailbox.name:
        score *= 0.01
    return score


def _deterministic_uniform(seed: bytes, key: str, modulo: int) -> int:
    digest = hmac.new(seed, key.encode("utf-8"), hashlib.sha256).digest()
    return int.from_bytes(digest[:8], "big") % modulo


def select_route(
    *,
    network: dict[str, RelayNode],
    conversation_secret: bytes,
    message_id: str,
    state: RouteState,
    max_attempts: int = 32,
) -> tuple[str, str, RouteState]:
    entries = [node for node in network.values() if node.role in ("entry", "both")]
    mailboxes = [node for node in network.values() if node.role in ("mailbox", "both")]
    if not entries or not mailboxes:
        raise ValueError("insufficient relays for route selection")

    seed = hkdf_derive(conversation_secret, message_id.encode("utf-8") + b"route")

    candidates: list[tuple[float, str, str]] = []
    for entry in entries:
        for mailbox in mailboxes:
            score = _weighted_score(entry=entry, mailbox=mailbox, state=state)
            if score <= 0:
                continue
            candidates.append((score, entry.name, mailbox.name))

    if not candidates:
        raise ValueError("no viable route candidates")

    total = sum(score for score, _, _ in candidates)
    pick = _deterministic_uniform(seed, "pick", 10_000) / 10_000.0 * total

    running = 0.0
    chosen_entry = candidates[0][1]
    chosen_mailbox = candidates[0][2]
    for score, entry_name, mailbox_name in candidates:
        running += score
        if pick <= running:
            chosen_entry, chosen_mailbox = entry_name, mailbox_name
            break

    for attempt in range(max_attempts):
        if chosen_entry != state.last_entry and chosen_mailbox != state.last_mailbox:
            break
        reroll = _deterministic_uniform(seed, f"reroll-{attempt}", len(candidates))
        _, chosen_entry, chosen_mailbox = candidates[reroll]

    new_state = RouteState(last_entry=chosen_entry, last_mailbox=chosen_mailbox)
    return chosen_entry, chosen_mailbox, new_state
