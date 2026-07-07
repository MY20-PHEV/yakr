from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import typer
from rich.console import Console
from rich.table import Table

from yakr_core.errors import ContactNotFoundError, YakrError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import OuterBlob
from yakr_core.session import Session
from yakr_core.store import FileLocalStore

app = typer.Typer(no_args_is_help=True, help="Yakr reference client")
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
) -> None:
    """Encrypt and store a message for a contact via the relay."""
    store = _store()
    identity = _require_identity(store)
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    encrypted = session.encrypt_text(message)
    store.save_contact(contact)

    payload = encrypted.outer_blob.to_relay_json()
    response = httpx.post(f"{_relay_url()}/v1/blobs", json=payload, timeout=10.0)
    if response.status_code != 201:
        raise YakrError(f"relay store failed: {response.status_code} {response.text}")

    console.print(f"[green]Sent to {contact_name}[/green] (seq={encrypted.inner_message.seq})")


@app.command("fetch")
def fetch_cmd(
    contact_name: str = typer.Argument(..., help="Contact to fetch messages from"),
) -> None:
    """Fetch and decrypt messages from the relay."""
    store = _store()
    identity = _require_identity(store)
    contact = store.get_contact(contact_name)
    if contact is None:
        raise ContactNotFoundError(f"unknown contact: {contact_name}")

    session = Session(identity, contact)
    deriver = session.mailbox_deriver(outbound=False)
    tags = deriver.candidate_epochs(session.recv_direction)

    fetched = 0
    for tag in tags:
        response = httpx.get(f"{_relay_url()}/v1/blobs/{tag.tag_b64}", timeout=10.0)
        if response.status_code != 200:
            raise YakrError(f"relay fetch failed: {response.status_code} {response.text}")

        for item in response.json():
            outer = OuterBlob.from_relay_json(item)
            try:
                inner = session.decrypt_outer(outer)
            except YakrError:
                continue
            store.save_inbound_message(contact_name, inner.seq, inner.body)
            store.save_contact(contact)
            console.print(f"[cyan]{contact_name}[/cyan]: {inner.body}")
            fetched += 1

    if fetched == 0:
        console.print(f"[yellow]No new messages from {contact_name}[/yellow]")
    else:
        console.print(f"[green]Fetched {fetched} message(s)[/green]")


@app.command("export-public")
def export_public_cmd(output: Path = typer.Option(None, "--output", "-o")) -> None:
    """Export the public bundle for sharing with contacts."""
    store = _store()
    identity = _require_identity(store)
    bundle = export_public_bundle(identity)
    target = output or (store.root / "public.json")
    target.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    console.print(f"[green]Wrote public bundle to {target}[/green]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
