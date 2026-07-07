from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

import httpx

from yakr_core.delivery_profile import (
    DeliveryProfile,
    mailbox_descriptors,
    profile_is_stale,
    relay_network_from_profile,
    verify_delivery_profile,
)
from yakr_core.identity import Contact, Identity
from yakr_core.onion import build_onion_packet
from yakr_core.relay import RelayNode, load_relay_network
from yakr_core.relay_ticket import issue_relay_ticket
from yakr_core.routing import RouteState, select_route
from yakr_core.session import EncryptedMessage
from yakr_core.store import FileLocalStore

logger = logging.getLogger(__name__)
DIRECT_TIMEOUT_SECS = 2.0


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


def load_route_nodes(route: str, *, network: dict[str, RelayNode] | None = None) -> tuple[RelayNode, RelayNode]:
    entry_name, mailbox_name = parse_route(route)
    network = network or load_relay_network(relays_path())
    try:
        return network[entry_name], network[mailbox_name]
    except KeyError as exc:
        raise ValueError(f"unknown relay in route: {exc}") from exc


def contact_relay_network(contact: Contact) -> dict[str, RelayNode] | None:
    if contact.delivery_profile is None:
        return None
    return relay_network_from_profile(contact.delivery_profile)


def mailbox_urls(contact: Contact | None, route: str | None) -> list[str]:
    if route is not None:
        network = None
        if contact is not None:
            network = contact_relay_network(contact)
        network = network or load_relay_network(relays_path())
        _, mailbox_name = parse_route(route)
        return [network[mailbox_name].url]
    if contact is not None and contact.delivery_profile is not None:
        mailboxes = mailbox_descriptors(contact.delivery_profile)
        if mailboxes:
            return [item.url for item in mailboxes]
    return [os.environ.get("YAKR_RELAY_URL", "http://127.0.0.1:8080").rstrip("/")]


def mailbox_url(route: str | None, *, contact: Contact | None = None) -> str:
    return mailbox_urls(contact, route)[0]


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


def try_direct_delivery(
    encrypted: EncryptedMessage,
    hints: list[str],
    *,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> bool:
    payload = encrypted.outer_blob.to_relay_json()
    for hint in hints:
        try:
            response = httpx.post(
                f"{hint.rstrip('/')}/v1/direct/blobs",
                json=payload,
                timeout=timeout,
            )
            if response.status_code in {200, 201}:
                return True
        except httpx.HTTPError:
            continue
    return False


def fetch_remote_profile(
    hints: list[str],
    signing_public: bytes,
    *,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> DeliveryProfile | None:
    for hint in hints:
        try:
            response = httpx.get(f"{hint.rstrip('/')}/v1/profile", timeout=timeout)
            if response.status_code != 200:
                continue
            profile = DeliveryProfile.from_b64(response.json()["profile"])
            verify_delivery_profile(profile, signing_public)
            return profile
        except (httpx.HTTPError, ValueError, KeyError):
            continue
    return None


def refresh_contact_profile(
    store: FileLocalStore,
    contact: Contact,
    *,
    warn_on_stale: bool = True,
) -> bool:
    profile = contact.delivery_profile
    if profile is None:
        return False
    if not profile_is_stale(profile):
        return False
    if warn_on_stale:
        logger.warning("delivery profile for %s is stale; attempting refresh", contact.name)
    refreshed = fetch_remote_profile(list(profile.direct_hints), contact.signing_public)
    if refreshed is None:
        return False
    contact.delivery_profile = refreshed
    store.save_contact(contact)
    return True


def resolve_contact_route(
    store: FileLocalStore,
    contact: Contact,
    route: str | None,
    message_id: str,
) -> str | None:
    if route is None:
        network = contact_relay_network(contact)
        if network is None:
            return None
        if len(network) == 1:
            only = next(iter(network.values()))
            if only.role == "both":
                return None
        state = store.load_route_state(contact.name)
        entry, mailbox, new_state = select_route(
            network=network,
            conversation_secret=contact.master_secret,
            message_id=message_id,
            state=state,
        )
        store.save_route_state(contact.name, new_state)
        return f"{entry},{mailbox}"
    if route == "auto":
        network = contact_relay_network(contact) or load_relay_network(relays_path())
        state = store.load_route_state(contact.name)
        entry, mailbox, new_state = select_route(
            network=network,
            conversation_secret=contact.master_secret,
            message_id=message_id,
            state=state,
        )
        store.save_route_state(contact.name, new_state)
        return f"{entry},{mailbox}"
    return route


def send_encrypted(
    encrypted: EncryptedMessage,
    *,
    relay_url: str,
    route: str | None = None,
    identity: Identity | None = None,
    contact: Contact | None = None,
    network: dict[str, RelayNode] | None = None,
) -> None:
    if route is None:
        relay_name = os.environ.get("YAKR_RELAY_NAME", "relay")
        payload = encrypted.outer_blob.to_relay_json()
        payload["ticket"] = _ticket(identity, contact, relay_name, "store")
        response = httpx.post(f"{relay_url}/v1/blobs", json=payload, timeout=10.0)
        if response.status_code != 201:
            raise RuntimeError(f"relay store failed: {response.status_code} {response.text}")
        return

    entry, mailbox = load_route_nodes(route, network=network)
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


def deliver_encrypted(
    encrypted: EncryptedMessage,
    *,
    contact: Contact,
    identity: Identity | None = None,
    route: str | None = None,
    store: FileLocalStore | None = None,
    allow_direct: bool = True,
    retry_on_stale: bool = True,
) -> str:
    """Deliver a message using direct P2P first, then profile-aware relay routing."""
    if store is not None and retry_on_stale:
        refresh_contact_profile(store, contact)

    profile = contact.delivery_profile
    if allow_direct and profile is not None and profile.direct_hints:
        if try_direct_delivery(encrypted, list(profile.direct_hints)):
            return "direct"

    if profile is not None and profile_is_stale(profile):
        logger.warning("using stale delivery profile for %s", contact.name)

    network = contact_relay_network(contact)
    resolved_route = route
    if resolved_route == "auto" or (resolved_route is None and network is not None and len(network) > 1):
        if store is None:
            raise ValueError("store required for automatic profile routing")
        resolved_route = resolve_contact_route(store, contact, route or "auto", encrypted.msg_id)

    relay_urls = mailbox_urls(contact, resolved_route)
    relay_url = relay_urls[0]

    try:
        send_encrypted(
            encrypted,
            relay_url=relay_url,
            route=resolved_route,
            identity=identity,
            contact=contact,
            network=network,
        )
    except RuntimeError:
        if store is not None and refresh_contact_profile(store, contact, warn_on_stale=True):
            return deliver_encrypted(
                encrypted,
                contact=contact,
                identity=identity,
                route=route,
                store=store,
                allow_direct=allow_direct,
                retry_on_stale=False,
            )
        raise

    return "relay" if resolved_route is None else f"two-hop:{resolved_route}"


def fetch_direct_blobs(
    mailbox_tag_b64: str,
    hints: list[str],
    *,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> list[dict[str, str | int]]:
    for hint in hints:
        try:
            response = httpx.get(
                f"{hint.rstrip('/')}/v1/direct/blobs/{mailbox_tag_b64}",
                timeout=timeout,
            )
            if response.status_code == 200:
                return response.json()
        except httpx.HTTPError:
            continue
    return []
