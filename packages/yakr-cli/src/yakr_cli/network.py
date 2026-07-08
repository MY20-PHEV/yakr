from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

import httpx

from yakr_core.http_client import yakr_get, yakr_post

from yakr_core.delivery_profile import (
    DeliveryProfile,
    mailbox_descriptors,
    profile_is_stale,
    relay_network_from_profile,
    verify_delivery_profile,
)
from yakr_core.identity import Contact, Identity
from yakr_core.onion import build_onion_packet
from yakr_core.presence import fresh_group_relay_urls, is_presence_fresh, resolve_operator_url
from yakr_core.relay import RelayNode, load_relay_network
from yakr_core.relay_ticket import issue_relay_ticket
from yakr_core.message import OuterBlob
from yakr_core.routing import RouteState, select_route
from yakr_core.session import EncryptedMessage, Session
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


def delivery_relay_network(
    contact: Contact,
    store: FileLocalStore | None,
) -> dict[str, RelayNode] | None:
    network: dict[str, RelayNode] = {}
    if contact.delivery_profile is not None:
        network.update(relay_network_from_profile(contact.delivery_profile))
    if store is not None:
        local_profile = store.load_local_profile()
        if local_profile is not None:
            for name, node in relay_network_from_profile(local_profile).items():
                network.setdefault(name, node)
    if not network:
        return None
    return _overlay_presence_urls(network, store)


def _overlay_presence_urls(
    network: dict[str, RelayNode],
    store: FileLocalStore | None,
) -> dict[str, RelayNode]:
    if store is None:
        return network
    updated: dict[str, RelayNode] = {}
    for name, node in network.items():
        url = resolve_operator_url(store, name, node.url)
        if url == node.url:
            updated[name] = node
        else:
            updated[name] = RelayNode(
                name=node.name,
                role=node.role,
                url=url,
                wrap_secret=node.wrap_secret,
            )
    return updated


def should_use_auto_two_hop(network: dict[str, RelayNode]) -> bool:
    """Multiple standalone mailbox relays use send failover, not onion routing."""
    if len(network) <= 1:
        return False
    if all(node.role == "both" for node in network.values()):
        return False
    has_entry = any(node.role in ("entry", "both") for node in network.values())
    has_mailbox = any(node.role in ("mailbox", "both") for node in network.values())
    return has_entry and has_mailbox


def _profile_mailbox_urls(
    profile: DeliveryProfile | None,
    *,
    store: FileLocalStore | None = None,
) -> list[str]:
    if profile is None:
        return []
    return [
        resolve_operator_url(store, descriptor.name, descriptor.url)
        for descriptor in mailbox_descriptors(profile)
    ]


def _append_unique_urls(urls: list[str], seen: set[str], candidates: list[str]) -> None:
    for url in candidates:
        normalized = url.rstrip("/")
        if normalized and normalized not in seen:
            urls.append(normalized)
            seen.add(normalized)


def _contact_profile_mailbox_urls(
    contact: Contact,
    *,
    store: FileLocalStore | None = None,
) -> list[str]:
    return _profile_mailbox_urls(contact.delivery_profile, store=store)


def _trust_graph_mailbox_urls(
    store: FileLocalStore,
    contact: Contact | None = None,
) -> list[str]:
    """Union of local, contact, all paired profiles, and fresh presence group relays."""
    seen: set[str] = set()
    urls: list[str] = []

    _append_unique_urls(urls, seen, local_mailbox_urls(store))

    if contact is not None:
        _append_unique_urls(urls, seen, _contact_profile_mailbox_urls(contact, store=store))

    for name in store.list_contacts():
        paired = store.get_contact(name)
        if paired is None:
            continue
        _append_unique_urls(urls, seen, _contact_profile_mailbox_urls(paired, store=store))

    _append_unique_urls(urls, seen, fresh_group_relay_urls(store))

    for payload in store.list_presences():
        if is_presence_fresh(payload):
            _append_unique_urls(urls, seen, [payload.reachable_url])

    return urls


def local_mailbox_urls(store: FileLocalStore) -> list[str]:
    return _profile_mailbox_urls(store.load_local_profile(), store=store)


def _env_relay_url() -> str | None:
    return os.environ.get("YAKR_RELAY_URL", "").rstrip("/") or None


def delivery_mailbox_urls(
    contact: Contact,
    route: str | None,
    *,
    store: FileLocalStore | None = None,
) -> list[str]:
    """Ordered relay URLs for storing a message (recipient mailboxes, then sender fallbacks)."""
    if route is not None:
        network = contact_relay_network(contact)
        network = network or (load_relay_network(relays_path()) if relays_path().exists() else None)
        if network is None:
            raise ValueError("route requires contact or relays.json network")
        _, mailbox_name = parse_route(route)
        return [network[mailbox_name].url]

    seen: set[str] = set()
    urls: list[str] = []
    _append_unique_urls(urls, seen, _profile_mailbox_urls(contact.delivery_profile, store=store))
    if store is not None:
        _append_unique_urls(urls, seen, local_mailbox_urls(store))
        _append_unique_urls(urls, seen, fresh_group_relay_urls(store))
    if urls:
        return urls

    env_relay = _env_relay_url()
    if env_relay:
        return [env_relay]

    raise ValueError(
        f"no relay route to deliver to {contact.name}: recipient advertises no relay "
        "and sender has no paired relay"
    )


def fetch_mailbox_urls(
    contact: Contact,
    route: str | None,
    *,
    store: FileLocalStore | None = None,
) -> list[str]:
    """Relay URLs to poll for inbound messages in a conversation."""
    if route is not None:
        return delivery_mailbox_urls(contact, route, store=store)

    if store is not None:
        urls = _trust_graph_mailbox_urls(store, contact)
        if urls:
            return urls

    env_relay = _env_relay_url()
    if env_relay:
        return [env_relay]

    raise ValueError(
        f"no relay route to fetch messages for {contact.name}: pair with a relay operator "
        "or receive via a contact who advertises one"
    )


def mailbox_urls(
    contact: Contact | None,
    route: str | None,
    *,
    store: FileLocalStore | None = None,
) -> list[str]:
    if contact is None:
        raise ValueError("contact required")
    return fetch_mailbox_urls(contact, route, store=store)


def mailbox_url(
    route: str | None,
    *,
    contact: Contact | None = None,
    store: FileLocalStore | None = None,
) -> str:
    return mailbox_urls(contact, route, store=store)[0]


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
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    identity: Identity | None = None,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> bool:
    payload = encrypted.outer_blob.to_relay_json()
    for hint in hints:
        try:
            response = yakr_post(
                f"{hint.rstrip('/')}/v1/direct/blobs",
                store=store,
                contact=contact,
                identity=identity,
                json=payload,
                timeout=timeout,
            )
            if response.status_code in {200, 201}:
                return True
        except (httpx.HTTPError, ValueError):
            continue
    return False


def fetch_remote_profile(
    hints: list[str],
    signing_public: bytes,
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> DeliveryProfile | None:
    for hint in hints:
        try:
            response = yakr_get(
                f"{hint.rstrip('/')}/v1/profile",
                store=store,
                contact=contact,
                timeout=timeout,
            )
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
    refreshed = fetch_remote_profile(list(profile.direct_hints), contact.signing_public, store=store)
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
    store: FileLocalStore | None = None,
) -> None:
    if route is None:
        relay_name = os.environ.get("YAKR_RELAY_NAME", "relay")
        payload = encrypted.outer_blob.to_relay_json()
        payload["ticket"] = _ticket(identity, contact, relay_name, "store")
        response = yakr_post(
            f"{relay_url}/v1/blobs",
            store=store,
            contact=contact,
            identity=identity,
            json=payload,
            timeout=10.0,
        )
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
    response = yakr_post(
        f"{entry.url}/v1/relay",
        store=store,
        contact=contact,
        identity=identity,
        json={
            "packet": packet_b64,
            "ticket": _ticket(identity, contact, entry.name, "forward") or store_ticket,
        },
        timeout=10.0,
    )
    if response.status_code != 202:
        raise RuntimeError(f"relay forward failed: {response.status_code} {response.text}")


def _relay_name_for_url(relay_url: str, network: dict[str, RelayNode] | None) -> str:
    normalized = relay_url.rstrip("/")
    if network is not None:
        for node in network.values():
            if node.url.rstrip("/") == normalized:
                return node.name
    return os.environ.get("YAKR_RELAY_NAME", "relay")


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
        if try_direct_delivery(encrypted, list(profile.direct_hints), store=store, contact=contact, identity=identity):
            return "direct"

    if profile is not None and profile_is_stale(profile):
        logger.warning("using stale delivery profile for %s", contact.name)

    network = delivery_relay_network(contact, store)
    resolved_route = route
    if resolved_route == "auto" or (
        resolved_route is None and network is not None and should_use_auto_two_hop(network)
    ):
        if store is None:
            raise ValueError("store required for automatic profile routing")
        resolved_route = resolve_contact_route(store, contact, route or "auto", encrypted.msg_id)

    relay_urls = delivery_mailbox_urls(contact, resolved_route, store=store)

    if resolved_route is not None:
        relay_url = relay_urls[0]
        try:
            send_encrypted(
                encrypted,
                relay_url=relay_url,
                route=resolved_route,
                identity=identity,
                contact=contact,
                network=network,
                store=store,
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
        return f"two-hop:{resolved_route}"

    errors: list[str] = []
    for relay_url in relay_urls:
        relay_name = _relay_name_for_url(relay_url, network)
        previous_name = os.environ.get("YAKR_RELAY_NAME")
        os.environ["YAKR_RELAY_NAME"] = relay_name
        try:
            send_encrypted(
                encrypted,
                relay_url=relay_url,
                route=None,
                identity=identity,
                contact=contact,
                network=network,
                store=store,
            )
            if len(relay_urls) > 1 and relay_url != relay_urls[0]:
                return f"relay-failover:{relay_name}"
            return "relay" if relay_name in {"relay", ""} else f"relay:{relay_name}"
        except (RuntimeError, httpx.HTTPError, ValueError) as exc:
            errors.append(f"{relay_url}: {exc}")
            logger.warning("relay delivery failed for %s via %s: %s", contact.name, relay_url, exc)
        finally:
            if previous_name is None:
                os.environ.pop("YAKR_RELAY_NAME", None)
            else:
                os.environ["YAKR_RELAY_NAME"] = previous_name

    if store is not None and retry_on_stale and refresh_contact_profile(store, contact, warn_on_stale=True):
        return deliver_encrypted(
            encrypted,
            contact=contact,
            identity=identity,
            route=route,
            store=store,
            allow_direct=allow_direct,
            retry_on_stale=False,
        )

    detail = "; ".join(errors) if errors else "no relay URLs"
    raise RuntimeError(f"all relay delivery attempts failed for {contact.name}: {detail}")


def resend_pending_for_contact(
    store: FileLocalStore,
    identity: Identity,
    contact_name: str,
    *,
    route: str | None = None,
) -> int:
    """Re-encrypt and deliver each pending outbound message; clear stale pending on success."""
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ValueError(f"unknown contact: {contact_name}")

    resent = 0
    for msg_id, _seq, body in list(store.list_outbound_pending(contact_name)):
        session = Session(identity, contact)
        encrypted = session.encrypt_text(body)
        store.save_contact(contact)
        store.save_outbound_pending(
            contact_name,
            encrypted.msg_id,
            encrypted.inner_message.seq,
            body,
        )
        try:
            deliver_encrypted(
                encrypted,
                contact=contact,
                identity=identity,
                route=route,
                store=store,
            )
        except RuntimeError:
            store.mark_outbound_delivered(contact_name, encrypted.msg_id)
            continue
        if store.mark_outbound_delivered(contact_name, msg_id):
            resent += 1
    return resent


def fetch_direct_blobs(
    mailbox_tag_b64: str,
    hints: list[str],
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    identity: Identity | None = None,
    timeout: float = DIRECT_TIMEOUT_SECS,
) -> list[dict[str, str | int]]:
    for hint in hints:
        try:
            response = yakr_get(
                f"{hint.rstrip('/')}/v1/direct/blobs/{mailbox_tag_b64}",
                store=store,
                contact=contact,
                identity=identity,
                timeout=timeout,
            )
            if response.status_code == 200:
                return response.json()
        except (httpx.HTTPError, ValueError):
            continue
    return []


def fetch_relay_blobs(
    mailbox_tag_b64: str,
    fetch_bases: list[str],
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    identity: Identity | None = None,
    timeout: float = 10.0,
) -> list[dict[str, str | int]]:
    """Poll each relay URL; skip unreachable hosts and merge unique ciphertexts."""
    items: list[dict[str, str | int]] = []
    seen: set[str] = set()
    for fetch_base in fetch_bases:
        try:
            response = yakr_get(
                f"{fetch_base.rstrip('/')}/v1/blobs/{mailbox_tag_b64}",
                store=store,
                contact=contact,
                identity=identity,
                timeout=timeout,
            )
            if response.status_code != 200:
                continue
            for item in response.json():
                ciphertext = str(item.get("ciphertext", ""))
                if ciphertext in seen:
                    continue
                seen.add(ciphertext)
                items.append(item)
        except (httpx.HTTPError, ValueError):
            continue
    return items
