from __future__ import annotations

import base64
import os
from pathlib import Path

import httpx

from yakr_core.identity import Contact, Identity
from yakr_core.message import OuterBlob
from yakr_core.onion import build_onion_packet
from yakr_core.relay import RelayNode, load_relay_network
from yakr_core.relay_ticket import issue_relay_ticket
from yakr_core.session import EncryptedMessage


def relays_path() -> Path:
    custom = os.environ.get("YAKR_RELAYS_FILE")
    if custom:
        return Path(custom)
    shared = Path("/data/shared/relays.json")
    if shared.exists():
        return shared
    return Path.cwd() / "relays.json"


def tickets_required() -> bool:
    return os.environ.get("YAKR_REQUIRE_TICKETS", "").lower() in {"1", "true", "yes"}


def parse_route(route: str) -> tuple[str, str]:
    parts = [part.strip() for part in route.split(",") if part.strip()]
    if len(parts) != 2:
        raise ValueError("route must be entry,mailbox")
    return parts[0], parts[1]


def load_route_nodes(route: str) -> tuple[RelayNode, RelayNode]:
    entry_name, mailbox_name = parse_route(route)
    network = load_relay_network(relays_path())
    try:
        return network[entry_name], network[mailbox_name]
    except KeyError as exc:
        raise ValueError(f"unknown relay in route: {exc}") from exc


def mailbox_url(route: str | None) -> str:
    if route is None:
        return os.environ.get("YAKR_RELAY_URL", "http://127.0.0.1:8080").rstrip("/")
    _, mailbox = load_route_nodes(route)
    return mailbox.url


def _ticket(
    identity: Identity | None,
    contact: Contact | None,
    relay_name: str,
    permission: str,
) -> str | None:
    if not tickets_required() or identity is None or contact is None or contact.contact_id is None:
        return None
    return issue_relay_ticket(
        identity,
        relay_name=relay_name,
        permissions=(permission,),
        contact_id=contact.contact_id,
    ).to_b64()


def send_encrypted(
    encrypted: EncryptedMessage,
    *,
    relay_url: str,
    route: str | None = None,
    identity: Identity | None = None,
    contact: Contact | None = None,
) -> None:
    if route is None:
        relay_name = os.environ.get("YAKR_RELAY_NAME", "relay")
        payload = encrypted.outer_blob.to_relay_json()
        payload["ticket"] = _ticket(identity, contact, relay_name, "store")
        response = httpx.post(f"{relay_url}/v1/blobs", json=payload, timeout=10.0)
        if response.status_code != 201:
            raise RuntimeError(f"relay store failed: {response.status_code} {response.text}")
        return

    entry, mailbox = load_route_nodes(route)
    packet = build_onion_packet(
        entry_wrap_secret=entry.wrap_secret,
        mailbox_wrap_secret=mailbox.wrap_secret,
        entry_relay_url=entry.url,
        mailbox_relay_url=mailbox.url,
        outer=encrypted.outer_blob,
    )
    packet_b64 = base64.urlsafe_b64encode(packet).decode("ascii").rstrip("=")
    store_ticket = _ticket(identity, contact, mailbox.name, "store")
    response = httpx.post(
        f"{entry.url}/v1/relay",
        json={
            "packet": packet_b64,
            "ticket": _ticket(identity, contact, entry.name, "forward") or store_ticket,
        },
        timeout=10.0,
    )
    if response.status_code != 202:
        raise RuntimeError(f"relay forward failed: {response.status_code} {response.text}")
