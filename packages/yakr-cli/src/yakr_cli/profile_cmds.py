from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

import httpx
import typer
from rich.console import Console

from yakr_core.delivery_profile import (
    DeliveryProfile,
    RelayDescriptor,
    create_delivery_profile,
    profile_is_stale,
    verify_delivery_profile,
)
from yakr_core.relay_authorization import (
    assert_publish_relays_allowed,
    authorized_publish_relays,
    self_relay_descriptor,
)
from yakr_core.profile_ack import relay_names_from_profile
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted
from yakr_cli.presence_cmds import publish_own_presence, relay_locations_changed

console = Console()
logger = logging.getLogger(__name__)
profile_app = typer.Typer(help="Delivery profile management")


def _store() -> FileLocalStore:
    from yakr_cli.main import _store

    return _store()


def _require_identity(store: FileLocalStore):
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def _relay_url() -> str:
    return os.environ.get("YAKR_RELAY_URL", "http://127.0.0.1:8080").rstrip("/")


def _authorized_descriptors(
    identity,
    store: FileLocalStore,
) -> list[RelayDescriptor]:
    contacts = [contact for name in store.list_contacts() if (contact := store.get_contact(name))]
    relay_url = os.environ.get("YAKR_RELAY_URL")
    relay_name = os.environ.get("YAKR_RELAY_NAME", identity.name)
    self_relay = None
    if relay_url:
        self_relay = self_relay_descriptor(
            identity,
            relay_url,
            relay_name,
            secrets.token_bytes(32),
        )
    return authorized_publish_relays(
        identity_name=identity.name,
        contacts=contacts,
        self_relay=self_relay,
    )


def build_local_profile(
    identity,
    *,
    store: FileLocalStore | None = None,
    direct_hint: str | None = None,
    version: int | None = None,
) -> DeliveryProfile:
    if store is None:
        store = _store()
    descriptors = _authorized_descriptors(identity, store)
    assert_publish_relays_allowed(descriptors, descriptors)
    return create_delivery_profile(
        identity,
        relay_descriptors=descriptors,
        direct_hints=[direct_hint] if direct_hint else [],
        version=version,
    )


@profile_app.command("publish")
def profile_publish(
    direct_port: int | None = typer.Option(None, "--direct-port", help="Publish direct P2P hint"),
    bump_version: bool = typer.Option(True, "--bump-version/--no-bump-version"),
) -> None:
    """Create or refresh the local delivery profile."""
    store = _store()
    identity = _require_identity(store)
    current = store.load_local_profile()
    version = 1
    if current is not None and bump_version:
        version = current.version + 1
    elif current is not None:
        version = current.version

    direct_hint = None
    if direct_port is not None:
        direct_hint = f"http://127.0.0.1:{direct_port}"

    profile = build_local_profile(identity, store=store, direct_hint=direct_hint, version=version)
    store.save_local_profile(profile)
    console.print(f"[green]Published delivery profile v{profile.version}[/green]")
    if profile.relay_descriptors:
        for relay in profile.relay_descriptors:
            console.print(f"[cyan]Relay:[/cyan] {relay.name} ({relay.url})")
    else:
        console.print("[yellow]No relay advertised (pair with a relay operator to add one)[/yellow]")
    if direct_hint:
        console.print(f"[cyan]Direct hint:[/cyan] {direct_hint}")

    if relay_locations_changed(current, profile):
        pushed = publish_own_presence(store, identity, quiet=True)
        if pushed:
            console.print(f"[green]Fan-out presence to {pushed} contact(s) (relay URL changed)[/green]")


@profile_app.command("show")
def profile_show(
    contact_name: str | None = typer.Argument(None, help="Contact name or local profile"),
) -> None:
    """Show the local profile or a contact's stored profile."""
    store = _store()
    if contact_name is None:
        profile = store.load_local_profile()
        if profile is None:
            console.print("[yellow]No local delivery profile published[/yellow]")
            raise typer.Exit(code=1)
        console.print(f"local v{profile.version} valid_until={profile.valid_until}")
        for hint in profile.direct_hints:
            console.print(f"  direct: {hint}")
        for relay in profile.relay_descriptors:
            console.print(f"  relay: {relay.name} ({relay.role}) {relay.url}")
        return

    contact = store.get_contact(contact_name)
    if contact is None or contact.delivery_profile is None:
        console.print(f"[yellow]No delivery profile stored for {contact_name}[/yellow]")
        raise typer.Exit(code=1)
    profile = contact.delivery_profile
    stale = profile_is_stale(profile)
    status = "stale" if stale else "fresh"
    console.print(f"{contact_name} v{profile.version} ({status})")
    for relay in profile.relay_descriptors:
        console.print(f"  relay: {relay.name} ({relay.role}) {relay.url}")


@profile_app.command("push")
def profile_push(
    contact_name: str = typer.Argument(..., help="Contact to update"),
) -> None:
    """Push the local delivery profile to a contact via encrypted message."""
    store = _store()
    identity = _require_identity(store)
    contact = store.get_contact(contact_name)
    if contact is None:
        console.print(f"[red]Unknown contact: {contact_name}[/red]")
        raise typer.Exit(code=1)

    profile = store.load_local_profile()
    if profile is None:
        profile = build_local_profile(identity, store=store)
        store.save_local_profile(profile)

    session = Session(identity, contact)
    encrypted = session.encrypt_profile(profile)
    store.save_contact(contact)
    store.save_profile_ack_pending(
        contact_name,
        encrypted.msg_id,
        profile_version=profile.version,
        relay_names=relay_names_from_profile(profile),
    )
    deliver_encrypted(
        encrypted,
        contact=contact,
        identity=identity,
        route=None,
    )
    console.print(f"[green]Pushed delivery profile v{profile.version} to {contact_name}[/green]")
