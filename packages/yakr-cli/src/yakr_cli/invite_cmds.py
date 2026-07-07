from __future__ import annotations

import base64
import threading
import time
from pathlib import Path

import httpx
import typer
import uvicorn
from rich.console import Console

from yakr_core.identity import Identity
from yakr_core.invite import (
    create_invite,
    invite_from_url,
    invite_to_url,
    safety_code,
    verify_invite,
)
from yakr_core.pairing import (
    PairingResponse,
    build_pairing_request,
    joiner_complete_pairing,
)
from yakr_core.store import FileLocalStore
from yakr_cli.rendezvous import RendezvousState, create_rendezvous_app

console = Console()
invite_app = typer.Typer(help="Invite-based contact pairing")


@invite_app.command("create")
def invite_create(
    listen_host: str = typer.Option("127.0.0.1", "--host"),
    listen_port: int = typer.Option(8090, "--port"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for a joiner"),
) -> None:
    """Create a signed invite and optionally serve rendezvous pairing."""
    from yakr_cli.main import _require_identity, _store

    store = _store()
    identity = _require_identity(store)
    rendezvous_hint = f"http://{listen_host}:{listen_port}"
    bundle = create_invite(identity, rendezvous_hint=rendezvous_hint)
    url = invite_to_url(bundle)
    code = safety_code(bundle)

    invite_path = store.root / "invites" / "latest.url"
    invite_path.parent.mkdir(parents=True, exist_ok=True)
    invite_path.write_text(url, encoding="utf-8")

    console.print(f"[green]Invite URL:[/green] {url}")
    console.print(f"[green]Safety code:[/green] {code}")

    if not wait:
        return

    state = RendezvousState(invite=bundle, identity=identity)
    app = create_rendezvous_app(state)
    config = uvicorn.Config(app, host=listen_host, port=listen_port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    console.print(f"[yellow]Waiting for joiner on {rendezvous_hint}…[/yellow]")
    while not state.consumed and time.time() < deadline:
        time.sleep(0.2)

    server.should_exit = True
    thread.join(timeout=2)

    if state.paired_contact is None:
        console.print("[red]No joiner completed pairing[/red]")
        raise typer.Exit(code=1)

    store.save_contact(state.paired_contact)
    console.print(f"[green]Paired with {state.paired_contact.name}[/green]")


@invite_app.command("accept")
def invite_accept(
    invite: str = typer.Argument(..., help="yakr://invite/... URL or path to invite file"),
    name: str | None = typer.Option(None, "--name", "-n", help="Local name for inviter contact"),
) -> None:
    """Accept an invite and complete pairing via rendezvous."""
    from yakr_cli.main import _require_identity, _store

    store = _store()
    identity = _require_identity(store)

    if invite.startswith("yakr://"):
        bundle = invite_from_url(invite)
    else:
        bundle = invite_from_url(Path(invite).read_text(encoding="utf-8").strip())

    verify_invite(bundle)
    console.print(f"[green]Safety code:[/green] {safety_code(bundle)}")

    request, ephemeral_private = build_pairing_request(
        identity,
        bundle,
        joiner_name=identity.name,
    )
    encoded_request = base64.urlsafe_b64encode(request.to_bytes()).decode("ascii").rstrip("=")
    response = httpx.post(
        f"{bundle.rendezvous_hint.rstrip('/')}/v1/pair",
        json={"request": encoded_request},
        timeout=10.0,
    )
    if response.status_code != 200:
        raise typer.Exit(code=1)

    pairing_response = PairingResponse.from_bytes(
        base64.urlsafe_b64decode(response.json()["response"] + "==")
    )
    contact = joiner_complete_pairing(identity, bundle, request, ephemeral_private, pairing_response)
    contact.name = name or bundle.inviter_name
    store.save_contact(contact)
    console.print(f"[green]Paired with {contact.name}[/green]")
