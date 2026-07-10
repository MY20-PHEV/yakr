from __future__ import annotations

from rich.console import Console

from yakr_core.crypto import derive_mailbox_secret
from yakr_core.profile_ack import record_profile_ack_on_receipt, relay_names_from_profile
from yakr_core.errors import ContactNotFoundError, DuplicateSeqError, YakrError
from yakr_core.identity import Contact, Identity
from yakr_core.message import OuterBlob, message_id
from yakr_core.presence import apply_presence_message
from yakr_core.privacy import fetch_tags_for_mode
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import (
    fetch_direct_blobs,
    fetch_mailbox_urls,
    fetch_relay_blobs,
    resolve_contact_route,
)
from yakr_cli.receipt_cmds import flush_pending_receipts, send_delivery_receipt

console = Console()


def _refresh_contact_send_state(store: FileLocalStore, contact: Contact) -> None:
    """Merge send-side ratchet state from disk after a nested receipt send."""
    persisted = store.get_contact(contact.name)
    if persisted is None:
        return
    contact.next_send_seq = persisted.next_send_seq
    contact.ratchet = persisted.ratchet


def resolve_fetch_route(
    store: FileLocalStore,
    contact: Contact,
    route: str | None,
) -> str | None:
    if route is None:
        return resolve_contact_route(store, contact, None, "fetch")
    if route == "auto":
        return resolve_contact_route(store, contact, "auto", "fetch")
    return route


def fetch_contact_inbound(
    store: FileLocalStore,
    identity: Identity,
    contact_name: str,
    *,
    route: str | None = None,
    wide: bool = False,
    quiet: bool = False,
) -> int:
    """Fetch and decrypt inbound messages from a single paired contact."""
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    flushed = flush_pending_receipts(store, identity, contact_name=contact_name, route=route)
    if flushed and not quiet:
        console.print(f"[green]Flushed {flushed} queued delivery receipt(s) for {contact_name}[/green]")

    deriver = session.mailbox_deriver(outbound=False)
    mailbox_secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)
    tags = fetch_tags_for_mode(
        deriver,
        session.recv_direction,
        contact.privacy_mode,
        mailbox_secret=mailbox_secret,
    )
    real_tag_set = {tag.tag_b64 for tag in deriver.candidate_epochs(session.recv_direction)}
    resolved_route = resolve_fetch_route(store, contact, route)
    fetch_bases = fetch_mailbox_urls(contact, resolved_route, store=store, wide=wide)
    direct_hints = list(contact.delivery_profile.direct_hints) if contact.delivery_profile else []

    fetched = 0
    metrics = store.load_privacy_metrics()
    for tag in tags:
        is_decoy = tag.tag_b64 not in real_tag_set
        items: list[tuple[str | None, dict[str, str | int]]] = []
        if direct_hints:
            for item in fetch_direct_blobs(
                tag.tag_b64, direct_hints, store=store, contact=contact, identity=identity
            ):
                items.append((None, item))
        for item in fetch_relay_blobs(
            tag.tag_b64, fetch_bases, store=store, contact=contact, identity=identity
        ):
            items.append((None, item))
            metrics.record_fetch(len(str(item.get("ciphertext", ""))), decoy=is_decoy)

        seen: set[str] = set()
        queue: list[dict[str, str | int]] = []
        for _fetch_base, item in items:
            ciphertext = str(item.get("ciphertext", ""))
            if ciphertext in seen:
                continue
            seen.add(ciphertext)
            queue.append(item)
        queue.sort(key=lambda blob: int(blob.get("stored_at", 0)))

        pending = list(queue)
        while pending:
            progressed = False
            still_pending: list[dict[str, str | int]] = []
            for item in pending:
                outer = OuterBlob.from_relay_json(item)
                try:
                    inner = session.decrypt_outer(outer)
                except DuplicateSeqError:
                    still_pending.append(item)
                    continue
                except YakrError:
                    continue
                progressed = True

                if inner.type == "profile" and inner.body:
                    profile = DeliveryProfile.from_b64(inner.body)
                    verify_delivery_profile(profile, contact.signing_public)
                    contact.delivery_profile = profile
                    store.save_contact(contact)
                    if not quiet:
                        console.print(
                            f"[green]Updated delivery profile for {contact_name} "
                            f"(v{profile.version})[/green]"
                        )
                    continue

                presence = None
                try:
                    presence = apply_presence_message(store, contact, inner)
                except YakrError:
                    pass
                if presence is not None:
                    store.save_contact(contact)
                    if not quiet:
                        console.print(
                            f"[green]Updated presence for {presence.operator_name} "
                            f"→ {presence.reachable_url}[/green]"
                        )
                    continue

                if inner.type == "receipt" and inner.message_id:
                    if store.mark_outbound_delivered(contact_name, inner.message_id) and not quiet:
                        console.print(f"[green]Delivery receipt for {inner.message_id[:12]}…[/green]")
                    record_profile_ack_on_receipt(store, contact, contact_name, inner.message_id)
                    store.save_contact(contact)
                    continue

                if inner.type != "text":
                    continue

                store.save_inbound_message(contact_name, inner, identity=identity)
                if not quiet:
                    console.print(f"[cyan]{contact_name}[/cyan]: {inner.body}")
                fetched += 1

                delivered_id = message_id(outer.ciphertext)
                receipt_route = resolve_contact_route(store, contact, route, delivered_id)
                if not send_delivery_receipt(
                    store,
                    identity,
                    contact_name,
                    delivered_id,
                    route=receipt_route,
                ):
                    if not quiet:
                        console.print(
                            f"[yellow]Receipt for {delivered_id[:12]}… queued "
                            f"(relay unreachable)[/yellow]"
                        )
                _refresh_contact_send_state(store, contact)
                store.save_contact(contact)
            if not progressed:
                break
            pending = still_pending

    store.save_privacy_metrics(metrics)
    return fetched


def fetch_all_contacts(
    store: FileLocalStore,
    identity: Identity,
    *,
    route: str | None = None,
    wide: bool = False,
) -> tuple[int, int]:
    """Fetch inbound messages from every paired contact."""
    store.sweep_expired_messages()
    store.sweep_expired_outbound()

    contacts = store.list_contacts()
    if not contacts:
        console.print("[yellow]No paired contacts to fetch[/yellow]")
        return 0, 0

    total_fetched = 0
    contacts_with_mail = 0
    for contact_name in contacts:
        try:
            count = fetch_contact_inbound(
                store,
                identity,
                contact_name,
                route=route,
                wide=wide,
                quiet=False,
            )
        except ValueError as exc:
            console.print(f"[yellow]Skipped {contact_name}: {exc}[/yellow]")
            continue
        if count > 0:
            contacts_with_mail += 1
            total_fetched += count
        else:
            console.print(f"[dim]No new messages from {contact_name}[/dim]")

    if total_fetched == 0:
        console.print("[yellow]No new messages from any contact[/yellow]")
    else:
        console.print(
            f"[green]Fetched {total_fetched} message(s) from "
            f"{contacts_with_mail} contact(s)[/green]"
        )
    return total_fetched, contacts_with_mail
