from __future__ import annotations

from collections.abc import Iterable

from yakr_core.delivery_profile import RelayDescriptor
from yakr_core.identity import Contact, Identity
from yakr_core.tls import endpoint_tls_spki_sha256


def _with_operator_tls(descriptor: RelayDescriptor, contact: Contact) -> RelayDescriptor:
    """Ensure relay descriptor carries the operator TLS pin from their signed profile."""
    if descriptor.tls_spki_sha256:
        return descriptor
    if contact.delivery_profile is None:
        return descriptor
    tls = contact.delivery_profile.endpoint_tls_spki_sha256
    if not tls:
        return descriptor
    return RelayDescriptor(
        name=descriptor.name,
        role=descriptor.role,
        url=descriptor.url,
        wrap_secret=descriptor.wrap_secret,
        tls_spki_sha256=tls,
    )


def relays_operated_by_contact(contact: Contact) -> list[RelayDescriptor]:
    """Relay descriptors operated by this contact (descriptor name matches contact name)."""
    if contact.delivery_profile is None:
        return []
    return [
        _with_operator_tls(descriptor, contact)
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
    identity: Identity,
    relay_url: str,
    relay_name: str,
    wrap_secret: bytes,
) -> RelayDescriptor | None:
    """Build a self-operated relay descriptor, or None if env points at someone else's relay."""
    if relay_name != identity.name:
        return None
    return RelayDescriptor(
        name=identity.name,
        role="both",
        url=relay_url.rstrip("/"),
        wrap_secret=wrap_secret,
        tls_spki_sha256=endpoint_tls_spki_sha256(identity),
    )
