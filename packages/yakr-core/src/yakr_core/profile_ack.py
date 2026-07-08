"""Track which peers have acknowledged our delivery profile (for send-path gating)."""

from __future__ import annotations

from yakr_core.delivery_profile import DeliveryProfile, mailbox_descriptors, verify_delivery_profile
from yakr_core.identity import Contact


def relay_names_from_profile(profile: DeliveryProfile) -> tuple[str, ...]:
    return tuple(descriptor.name for descriptor in mailbox_descriptors(profile))


def apply_peer_profile_ack(contact: Contact, profile: DeliveryProfile) -> None:
    """Record that this peer has acknowledged our delivery profile at ``profile.version``."""
    contact.peer_acked_my_profile_version = profile.version
    contact.peer_acked_my_relay_names = relay_names_from_profile(profile)


def apply_peer_profile_ack_from_bytes(
    contact: Contact,
    profile_bytes: bytes,
    signing_public: bytes,
) -> None:
    if not profile_bytes:
        return
    profile = DeliveryProfile.from_bytes(profile_bytes)
    verify_delivery_profile(profile, signing_public)
    apply_peer_profile_ack(contact, profile)


def apply_peer_profile_ack_pending(
    contact: Contact,
    *,
    profile_version: int,
    relay_names: tuple[str, ...],
) -> None:
    if profile_version > contact.peer_acked_my_profile_version:
        contact.peer_acked_my_profile_version = profile_version
        contact.peer_acked_my_relay_names = relay_names


def record_profile_ack_on_receipt(
    store: "FileLocalStore",
    contact: Contact,
    contact_name: str,
    delivered_id: str,
) -> None:
    """Update peer profile ack when a pushed profile message is receipted."""
    from yakr_core.store import FileLocalStore

    if not isinstance(store, FileLocalStore):
        return
    pending = store.take_profile_ack_pending(contact_name, delivered_id)
    if pending is None:
        return
    profile_version, relay_names = pending
    apply_peer_profile_ack_pending(
        contact,
        profile_version=profile_version,
        relay_names=relay_names,
    )

