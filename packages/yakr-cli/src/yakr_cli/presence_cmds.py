from __future__ import annotations

import logging
import os

import typer
from rich.console import Console

from yakr_core.identity import Identity
from yakr_core.presence import PresencePayload, is_presence_fresh
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted

console = Console()
logger = logging.getLogger(__name__)
presence_app = typer.Typer(help="Ephemeral relay reachability (presence)")


def _store() -> FileLocalStore:
    from yakr_cli.main import _store

    return _store()


def _require_identity(store: FileLocalStore) -> Identity:
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def relay_locations_changed(
    old_profile,
    new_profile,
) -> bool:
    """True when any relay descriptor URL changed between profile versions."""
    if old_profile is None:
        return bool(new_profile.relay_descriptors)
    old_map = {relay.name: relay.url for relay in old_profile.relay_descriptors}
    new_map = {relay.name: relay.url for relay in new_profile.relay_descriptors}
    return old_map != new_map


def own_presence_payloads(store: FileLocalStore, identity: Identity) -> list[PresencePayload]:
    """Build presence payloads for relays this operator advertises in their profile."""
    profile = store.load_local_profile()
    if profile is None:
        return []
    payloads: list[PresencePayload] = []
    for relay in profile.relay_descriptors:
        if relay.name != identity.name:
            continue
        payloads.append(
            PresencePayload.for_operator(
                relay.name,
                relay.url,
                relay_active=True,
            )
        )
    return payloads


def broadcast_presence(
    store: FileLocalStore,
    identity: Identity,
    payloads: list[PresencePayload],
    *,
    contact_name: str | None = None,
    quiet: bool = False,
) -> int:
    """Fan out presence to paired contacts via encrypted relay delivery."""
    if not payloads:
        return 0

    targets = [contact_name] if contact_name else store.list_contacts()
    delivered = 0
    for name in targets:
        contact = store.get_contact(name)
        if contact is None:
            continue
        session = Session(identity, contact)
        for payload in payloads:
            encrypted = session.encrypt_presence(payload)
            store.save_contact(contact)
            try:
                deliver_encrypted(
                    encrypted,
                    contact=contact,
                    identity=identity,
                    route=None,
                    store=store,
                )
                delivered += 1
                if not quiet:
                    console.print(
                        f"[green]Pushed presence for {payload.operator_name} "
                        f"→ {payload.reachable_url} to {name}[/green]"
                    )
            except RuntimeError as exc:
                logger.warning("presence delivery to %s failed: %s", name, exc)
                if not quiet:
                    console.print(f"[yellow]Presence to {name} failed: {exc}[/yellow]")

    for payload in payloads:
        store.save_presence(payload, source_contact=identity.name)
    return delivered


def publish_own_presence(
    store: FileLocalStore,
    identity: Identity,
    *,
    contact_name: str | None = None,
    quiet: bool = False,
) -> int:
    payloads = own_presence_payloads(store, identity)
    if not payloads and not quiet:
        relay_url = os.environ.get("YAKR_RELAY_URL", "").rstrip("/")
        relay_name = os.environ.get("YAKR_RELAY_NAME", identity.name)
        if relay_url:
            payloads = [PresencePayload.for_operator(relay_name, relay_url)]
    return broadcast_presence(store, identity, payloads, contact_name=contact_name, quiet=quiet)


@presence_app.command("push")
def presence_push(
    contact_name: str | None = typer.Argument(
        None,
        help="Single contact to update (default: all paired contacts)",
    ),
) -> None:
    """Publish ephemeral relay location to paired contacts."""
    store = _store()
    identity = _require_identity(store)
    count = publish_own_presence(store, identity, contact_name=contact_name)
    if count == 0:
        console.print("[yellow]No presence published (no self relay in profile or env)[/yellow]")
        raise typer.Exit(code=1)


@presence_app.command("show")
def presence_show(
    operator_name: str | None = typer.Argument(None, help="Operator name (default: all cached)"),
) -> None:
    """Show cached relay presence hints."""
    store = _store()
    if operator_name is not None:
        payload = store.load_presence(operator_name)
        if payload is None:
            console.print(f"[yellow]No presence cached for {operator_name}[/yellow]")
            raise typer.Exit(code=1)
        status = "fresh" if is_presence_fresh(payload) else "stale"
        console.print(
            f"{payload.operator_name}: {payload.reachable_url} "
            f"(active={payload.relay_active}, {status}, until={payload.valid_until})"
        )
        return

    entries = store.list_presences()
    if not entries:
        console.print("[yellow]No cached presence[/yellow]")
        raise typer.Exit(code=1)
    for payload in entries:
        status = "fresh" if is_presence_fresh(payload) else "stale"
        console.print(
            f"{payload.operator_name}: {payload.reachable_url} "
            f"(active={payload.relay_active}, {status})"
        )
