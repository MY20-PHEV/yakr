from __future__ import annotations

from collections.abc import Iterable

from yakr_core.delivery_profile import RelayDescriptor
from yakr_core.identity import Contact


def relays_operated_by_contact(contact: Contact) -> list[RelayDescriptor]:
    """Relay descriptors operated by this contact (descriptor name matches contact name)."""
    if contact.delivery_profile is None:
        return []
    return [
        descriptor
        for descriptor in contact.delivery_profile.relay_descriptors
        if descriptor.name == contact.name
    ]


def authorized_publish_relays(
    *,
    identity_name: str,
    contacts: Iterable[Contact],
    self_relay: RelayDescriptor | None = None,
) -> list[RelayDescriptor]:
    """Relays this identity may advertise in its own delivery profile."""
    seen_urls: set[str] = set()
    authorized: list[RelayDescriptor] = []

    if self_relay is not None:
        if self_relay.name != identity_name:
            raise ValueError("self-operated relay name must match identity name")
        authorized.append(self_relay)
        seen_urls.add(self_relay.url.rstrip("/"))

    for contact in contacts:
        for descriptor in relays_operated_by_contact(contact):
            url = descriptor.url.rstrip("/")
            if url in seen_urls:
                continue
            authorized.append(descriptor)
            seen_urls.add(url)

    return authorized


def assert_publish_relays_allowed(
    relay_descriptors: list[RelayDescriptor],
    authorized: list[RelayDescriptor],
) -> None:
    """Raise if any advertised relay is not operated by a paired contact (or self)."""
    authorized_urls = {descriptor.url.rstrip("/") for descriptor in authorized}
    for descriptor in relay_descriptors:
        if descriptor.url.rstrip("/") not in authorized_urls:
            raise ValueError(
                f"cannot advertise relay {descriptor.name!r} at {descriptor.url}: "
                "not paired with that relay operator"
            )


def self_relay_descriptor(
    identity_name: str,
    relay_url: str,
    relay_name: str,
    wrap_secret: bytes,
) -> RelayDescriptor | None:
    """Build a self-operated relay descriptor, or None if env points at someone else's relay."""
    if relay_name != identity_name:
        return None
    return RelayDescriptor(
        name=identity_name,
        role="both",
        url=relay_url.rstrip("/"),
        wrap_secret=wrap_secret,
    )
