from __future__ import annotations

import secrets

import pytest

from yakr_core.relay import RelayNode
from yakr_core.routing import RouteState, select_route


def _network() -> dict[str, RelayNode]:
    return {
        "alpha": RelayNode("alpha", "both", "http://alpha", secrets.token_bytes(32)),
        "bravo": RelayNode("bravo", "both", "http://bravo", secrets.token_bytes(32)),
        "charlie": RelayNode("charlie", "both", "http://charlie", secrets.token_bytes(32)),
        "delta": RelayNode("delta", "both", "http://delta", secrets.token_bytes(32)),
    }


def test_route_selection_avoids_immediate_reuse() -> None:
    network = _network()
    secret = secrets.token_bytes(32)
    state = RouteState()

    routes: list[tuple[str, str]] = []
    for index in range(100):
        message_id = f"msg-{index}"
        entry, mailbox, state = select_route(
            network=network,
            conversation_secret=secret,
            message_id=message_id,
            state=state,
        )
        routes.append((entry, mailbox))

    for (entry_a, mailbox_a), (entry_b, mailbox_b) in zip(routes, routes[1:], strict=False):
        assert not (entry_a == entry_b and mailbox_a == mailbox_b)


def test_route_selection_is_reproducible() -> None:
    network = _network()
    secret = secrets.token_bytes(32)
    state = RouteState()

    first = select_route(
        network=network,
        conversation_secret=secret,
        message_id="stable-id",
        state=state,
    )
    second = select_route(
        network=network,
        conversation_secret=secret,
        message_id="stable-id",
        state=state,
    )
    assert first[:2] == second[:2]
