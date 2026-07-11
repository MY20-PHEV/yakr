from __future__ import annotations

import logging

import httpx
import typer
from rich.console import Console

from yakr_core.identity import Identity
from yakr_core.ratchet import RatchetState
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted

console = Console()
logger = logging.getLogger(__name__)
receipts_app = typer.Typer(help="Delivery receipt queue and flush")


def _ratchet_snapshot(contact) -> dict:
    if contact.ratchet is None:
        raise ValueError("contact missing ratchet state")
    return contact.ratchet.to_dict()


def _restore_ratchet_snapshot(contact, snapshot: dict) -> None:
    contact.ratchet = RatchetState.from_dict(snapshot)


def _store() -> FileLocalStore:
    from yakr_cli.main import _store

    return _store()


def _require_identity(store: FileLocalStore) -> Identity:
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def _reverse_route(route: str | None) -> str | None:
    """Single-hop receipts use the same mailbox failover path as sends."""
    _ = route
    return None


def send_delivery_receipt(
    store: FileLocalStore,
    identity: Identity,
    contact_name: str,
    delivered_id: str,
    *,
    route: str | None = None,
) -> bool:
    """Send a delivery receipt; queue in SQLite if the relay is unreachable."""
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ValueError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    ratchet_snapshot = _ratchet_snapshot(contact)
    send_seq_before = contact.next_send_seq
    receipt = session.encrypt_receipt(delivered_id)
    _restore_ratchet_snapshot(contact, ratchet_snapshot)
    store.atomic_persist_contact(contact)
    reverse_route = _reverse_route(route)
    try:
        deliver_encrypted(
            receipt,
            contact=contact,
            identity=identity,
            route=reverse_route,
            store=store,
            allow_direct=False,
        )
        store.delete_pending_receipt(contact_name, delivered_id)
        return True
    except (RuntimeError, httpx.HTTPError, ValueError) as exc:
        _restore_ratchet_snapshot(contact, ratchet_snapshot)
        contact.next_send_seq = send_seq_before
        store.atomic_persist_contact(contact)
        logger.warning("receipt delivery to %s failed: %s", contact_name, exc)
        store.save_pending_receipt(contact_name, delivered_id, route=route)
        return False


def flush_pending_receipts(
    store: FileLocalStore,
    identity: Identity,
    *,
    contact_name: str | None = None,
    route: str | None = None,
) -> int:
    """Retry queued delivery receipts; return count delivered."""
    sent = 0
    for name, delivered_id, stored_route in list(store.list_pending_receipts(contact_name)):
        if send_delivery_receipt(
            store,
            identity,
            name,
            delivered_id,
            route=route if route is not None else stored_route,
        ):
            sent += 1
    return sent


@receipts_app.command("flush")
def receipts_flush(
    contact_name: str | None = typer.Argument(
        None,
        help="Contact to flush receipts for (default: all queued)",
    ),
    route: str | None = typer.Option(None, "--route", help="Two-hop route for receipt delivery"),
) -> None:
    """Retry delivery receipts that failed during an earlier fetch."""
    store = _store()
    identity = _require_identity(store)
    pending = store.list_pending_receipts(contact_name)
    if not pending:
        console.print("[green]No queued delivery receipts[/green]")
        return
    sent = flush_pending_receipts(store, identity, contact_name=contact_name, route=route)
    if sent == 0:
        console.print("[yellow]Queued receipts remain (relay still unreachable?)[/yellow]")
        raise typer.Exit(code=1)
    remaining = len(store.list_pending_receipts(contact_name))
    console.print(f"[green]Delivered {sent} receipt(s); {remaining} still queued[/green]")


@receipts_app.command("pending")
def receipts_pending(
    contact_name: str | None = typer.Argument(None, help="Filter by contact"),
) -> None:
    """List delivery receipts waiting for relay connectivity."""
    store = _store()
    pending = store.list_pending_receipts(contact_name)
    if not pending:
        console.print("[green]No queued delivery receipts[/green]")
        return
    for name, delivered_id, route in pending:
        route_label = route or "direct/failover"
        console.print(f"{name}: {delivered_id[:12]}… route={route_label}")
