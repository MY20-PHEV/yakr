from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from yakr_core.ephemeral import DEFAULT_BLOB_TTL_MS
from yakr_core.crypto import derive_mailbox_secret
from yakr_core.delivery_profile import DeliveryProfile, verify_delivery_profile
from yakr_core.errors import ContactNotFoundError, YakrError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import OuterBlob, message_id
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.invite_cmds import invite_app
from yakr_cli.network import (
    deliver_encrypted,
    delivery_mailbox_urls,
    fetch_direct_blobs,
    fetch_mailbox_urls,
    fetch_relay_blobs,
    resend_pending_for_contact,
    resolve_contact_route,
)
from yakr_core.privacy import SIZE_4K, fetch_tags_for_mode, generate_dummy_ciphertext
from yakr_cli.privacy_cmds import privacy_app

from yakr_cli.profile_cmds import profile_app

app = typer.Typer(no_args_is_help=True, help="Yakr reference client")
app.add_typer(invite_app, name="invite")
app.add_typer(profile_app, name="profile")
app.add_typer(privacy_app, name="privacy")
console = Console()


def _home() -> Path:
    if env_home := os.environ.get("YAKR_HOME"):
        return Path(env_home)
    name = os.environ.get("YAKR_NAME", "default")
    return Path.home() / ".yakr" / name


def _relay_url() -> str:
    return os.environ.get("YAKR_RELAY_URL", "http://127.0.0.1:8080").rstrip("/")


def _store() -> FileLocalStore:
    return FileLocalStore(_home())


def _resolve_route(
    store: FileLocalStore,
    contact: Contact,
    route: str | None,
    message_id: str,
) -> str | None:
    if route is None:
        return resolve_contact_route(store, contact, None, message_id)
    if route == "auto":
        return resolve_contact_route(store, contact, "auto", message_id)
    return route


def _require_identity(store: FileLocalStore) -> Identity:
    identity = store.load_identity()
    if identity is None:
        raise typer.Exit(code=1)
    return identity


@app.command("init")
def init_cmd(
    name: str | None = typer.Option(None, "--name", "-n", help="Local identity name"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing identity"),
) -> None:
    """Create a new local identity."""
    resolved_name = name or os.environ.get("YAKR_NAME")
    if not resolved_name:
        console.print("[red]Provide --name or set YAKR_NAME[/red]")
        raise typer.Exit(code=1)
    os.environ["YAKR_NAME"] = resolved_name
    store = _store()
    if store.identity_path.exists() and not force:
        console.print(f"[red]Identity already exists at {store.identity_path}[/red]")
        raise typer.Exit(code=1)

    identity = Identity.generate(resolved_name)
    store.save_identity(identity)
    console.print(f"[green]Initialized identity '{resolved_name}'[/green]")
    console.print(f"Public bundle: {store.root / 'public.json'}")


@app.command("show")
def show_cmd() -> None:
    """Show local identity details."""
    store = _store()
    identity = store.load_identity()
    if identity is None:
        console.print("[red]No identity found. Run `yakr init` first.[/red]")
        raise typer.Exit(code=1)

    table = Table(title="Identity")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("name", identity.name)
    table.add_row("device_id", identity.device_id)
    table.add_row("home", str(store.root))
    table.add_row("relay", _relay_url())
    console.print(table)


@app.command("contact-add")
def contact_add_cmd(
    name: str = typer.Argument(..., help="Contact name"),
    bundle: Path = typer.Argument(..., help="Path to contact public.json"),
) -> None:
    """Add a contact from a public bundle file."""
    store = _store()
    identity = _require_identity(store)
    if not bundle.exists():
        console.print(f"[red]Bundle not found: {bundle}[/red]")
        raise typer.Exit(code=1)

    remote_bundle = json.loads(bundle.read_text(encoding="utf-8"))
    contact = Contact.establish(identity, name, remote_bundle)
    store.save_contact(contact)
    console.print(f"[green]Added contact '{name}'[/green]")


@app.command("send")
def send_cmd(
    contact_name: str = typer.Argument(..., help="Recipient contact name"),
    message: str = typer.Argument(..., help="Message body"),
    route: str | None = typer.Option(None, "--route", help="entry,mailbox or auto"),
) -> None:
    """Encrypt and deliver a message for a contact via the relay."""
    store = _store()
    identity = _require_identity(store)
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    encrypted = session.encrypt_text(message)
    store.save_contact(contact)
    store.save_outbound_pending(contact_name, encrypted.msg_id, encrypted.inner_message.seq, message)

    mode = deliver_encrypted(
        encrypted,
        contact=contact,
        identity=identity,
        route=route,
        store=store,
    )
    metrics = store.load_privacy_metrics()
    metrics.record_send(len(encrypted.outer_blob.ciphertext), padding_bytes=encrypted.padding_bytes)
    if contact.privacy_mode == "high":
        _send_dummy_blob(store, contact, identity, session, route)
        metrics.dummy_blobs_sent += 1
    store.save_privacy_metrics(metrics)
    console.print(
        f"[green]Sent to {contact_name}[/green] "
        f"({mode}, privacy={contact.privacy_mode}, seq={encrypted.inner_message.seq})"
    )


@app.command("fetch")
def fetch_cmd(
    contact_name: str = typer.Argument(..., help="Contact to fetch messages from"),
    route: str | None = typer.Option(None, "--route", help="Two-hop route for delivery receipts"),
) -> None:
    """Fetch and decrypt messages from the relay."""
    store = _store()
    identity = _require_identity(store)
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    store.sweep_expired_messages()
    store.sweep_expired_outbound()
    deriver = session.mailbox_deriver(outbound=False)
    mailbox_secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)
    tags = fetch_tags_for_mode(
        deriver,
        session.recv_direction,
        contact.privacy_mode,
        mailbox_secret=mailbox_secret,
    )
    real_tag_set = {tag.tag_b64 for tag in deriver.candidate_epochs(session.recv_direction)}
    resolved_route = _resolve_route(store, contact, route, "fetch") if route else None
    fetch_bases = fetch_mailbox_urls(contact, resolved_route, store=store)
    direct_hints = list(contact.delivery_profile.direct_hints) if contact.delivery_profile else []

    fetched = 0
    metrics = store.load_privacy_metrics()
    for tag in tags:
        is_decoy = tag.tag_b64 not in real_tag_set
        items: list[tuple[str | None, dict[str, str | int]]] = []
        if direct_hints:
            for item in fetch_direct_blobs(tag.tag_b64, direct_hints):
                items.append((None, item))
        for item in fetch_relay_blobs(tag.tag_b64, fetch_bases):
            items.append((None, item))
            metrics.record_fetch(len(str(item.get("ciphertext", ""))), decoy=is_decoy)

        seen: set[str] = set()
        for fetch_base, item in items:
            ciphertext = str(item.get("ciphertext", ""))
            if ciphertext in seen:
                continue
            seen.add(ciphertext)
            outer = OuterBlob.from_relay_json(item)
            try:
                inner = session.decrypt_outer(outer)
            except YakrError:
                continue

            if inner.type == "profile" and inner.body:
                profile = DeliveryProfile.from_b64(inner.body)
                verify_delivery_profile(profile, contact.signing_public)
                contact.delivery_profile = profile
                store.save_contact(contact)
                console.print(
                    f"[green]Updated delivery profile for {contact_name} "
                    f"(v{profile.version})[/green]"
                )
                continue

            if inner.type == "receipt" and inner.message_id:
                if store.mark_outbound_delivered(contact_name, inner.message_id):
                    console.print(f"[green]Delivery receipt for {inner.message_id[:12]}…[/green]")
                continue

            if inner.type != "text":
                continue

            store.save_inbound_message(contact_name, inner, identity=identity)
            store.save_contact(contact)
            console.print(f"[cyan]{contact_name}[/cyan]: {inner.body}")
            fetched += 1

            delivered_id = message_id(outer.ciphertext)
            receipt = session.encrypt_receipt(delivered_id)
            store.save_contact(contact)
            reverse_route = None
            if resolved_route:
                entry_name, mailbox_name = resolved_route.split(",")
                reverse_route = f"{mailbox_name.strip()},{entry_name.strip()}"
            deliver_encrypted(
                receipt,
                contact=contact,
                identity=identity,
                route=reverse_route,
                store=store,
                allow_direct=False,
            )

    store.save_privacy_metrics(metrics)
    if fetched == 0:
        console.print(f"[yellow]No new messages from {contact_name}[/yellow]")
    else:
        console.print(f"[green]Fetched {fetched} message(s)[/green]")


@app.command("pending")
def pending_cmd(
    contact_name: str = typer.Argument(..., help="Contact to inspect"),
) -> None:
    """List outbound messages still awaiting delivery receipts."""
    store = _store()
    pending = store.list_outbound_pending(contact_name)
    if not pending:
        console.print(f"[green]No pending messages for {contact_name}[/green]")
        return
    for msg_id, seq, body in pending:
        console.print(f"seq={seq} id={msg_id[:12]}… body={body!r}")


@app.command("resend")
def resend_cmd(
    contact_name: str = typer.Argument(..., help="Contact to resend pending messages for"),
    route: str | None = typer.Option(None, "--route", help="entry,mailbox or auto"),
) -> None:
    """Re-encrypt and deliver outbound messages still awaiting delivery receipts."""
    store = _store()
    identity = _require_identity(store)
    if store.get_contact(contact_name) is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    count = resend_pending_for_contact(store, identity, contact_name, route=route)
    if count == 0:
        console.print(f"[yellow]No pending messages resent for {contact_name}[/yellow]")
    else:
        console.print(f"[green]Resent {count} pending message(s) to {contact_name}[/green]")


@app.command("export-public")
def export_public_cmd(output: Path = typer.Option(None, "--output", "-o")) -> None:
    """Export the public bundle for sharing with contacts."""
    store = _store()
    identity = _require_identity(store)
    bundle = export_public_bundle(identity)
    target = output or (store.root / "public.json")
    target.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote public bundle to {target}[/green]")


def _send_dummy_blob(
    store: FileLocalStore,
    contact: Contact,
    identity: Identity,
    session: Session,
    route: str | None,
) -> None:
    deriver = session.mailbox_deriver(outbound=True)
    mailbox_secret = derive_mailbox_secret(contact.master_secret, session.send_direction)
    decoy = fetch_tags_for_mode(
        deriver,
        session.send_direction,
        "high",
        mailbox_secret=mailbox_secret,
        lookback=0,
    )[0]
    dummy = generate_dummy_ciphertext(size_class=SIZE_4K)
    outer = OuterBlob(
        version=1,
        mailbox_tag=decoy.tag,
        expires_at=int(time.time() * 1000) + DEFAULT_BLOB_TTL_MS,
        ciphertext=dummy,
    )
    relay_url = delivery_mailbox_urls(contact, route, store=store)[0]
    httpx.post(f"{relay_url}/v1/blobs", json=outer.to_relay_json(), timeout=5.0)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
