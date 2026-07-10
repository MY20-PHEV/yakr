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
from yakr_core.pairing import OFFLINE_RENDEZVOUS_HINT
from yakr_core.store import FileLocalStore
from yakr_cli.profile_cmds import build_local_profile
from yakr_cli.offline_cmds import offline_app
from yakr_cli.relay_wait_cmds import relay_app
from yakr_cli.rendezvous import RendezvousState, create_rendezvous_app

console = Console()
invite_app = typer.Typer(help="Invite-based contact pairing")
invite_app.add_typer(offline_app, name="offline")
invite_app.add_typer(relay_app, name="relay")


@invite_app.command("create")
def invite_create(
    listen_host: str = typer.Option("127.0.0.1", "--host"),
    listen_port: int = typer.Option(8090, "--port"),
    rendezvous: str | None = typer.Option(None, "--rendezvous", help="Group relay URL for pairing"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for a joiner"),
    offline: bool = typer.Option(False, "--offline", help="In-person QR pairing only (no rendezvous server)"),
    hybrid_pq: bool = typer.Option(False, "--hybrid/--no-hybrid", help="Publish hybrid PQ invite"),
    qr_out: Path | None = typer.Option(None, "--qr-out", help="Write invite QR PNG"),
) -> None:
    """Create a signed invite and optionally serve rendezvous pairing."""
    from yakr_cli.main import _require_identity, _store

    store = _store()
    identity = _require_identity(store)
    rendezvous_hint = OFFLINE_RENDEZVOUS_HINT if offline else (rendezvous or f"http://{listen_host}:{listen_port}")
    bundle = create_invite(identity, rendezvous_hint=rendezvous_hint, hybrid_pq=hybrid_pq)
    url = invite_to_url(bundle)
    code = safety_code(bundle)

    local_profile = store.load_local_profile()
    if local_profile is None:
        local_profile = build_local_profile(identity, store=store, direct_hint=rendezvous_hint)
        store.save_local_profile(local_profile)
    inviter_profile = local_profile.to_bytes()

    invite_path = store.root / "invites" / "latest.url"
    invite_path.parent.mkdir(parents=True, exist_ok=True)
    invite_path.write_text(url, encoding="utf-8")

    console.print(f"[green]Invite URL:[/green] {url}")
    console.print(f"[green]Safety code:[/green] {code}")
    if offline:
        console.print("[yellow]Offline pairing:[/yellow] show invite QR, then run:")
        console.print("  joiner: yakr invite offline joiner-start <invite-url>")
        console.print("  inviter: yakr invite offline inviter-respond <pair-request-url>")
        console.print("  joiner: yakr invite offline joiner-finish <pair-response-url>")
        if qr_out is not None:
            from yakr_cli.qr_util import url_to_qr_png

            qr_out.parent.mkdir(parents=True, exist_ok=True)
            qr_out.write_bytes(url_to_qr_png(url))
            console.print(f"[cyan]QR PNG:[/cyan] {qr_out}")
        return

    if not wait:
        return

    local_hint = f"http://{listen_host}:{listen_port}"
    if rendezvous_hint.rstrip("/") != local_hint.rstrip("/"):
        from yakr_cli.relay_pairing import inviter_wait_on_relay

        console.print(f"[yellow]Waiting for joiner via relay {rendezvous_hint}…[/yellow]")
        _, contact = inviter_wait_on_relay(
            rendezvous_hint,
            identity,
            bundle,
            inviter_profile=inviter_profile,
            timeout_secs=120.0,
        )
        store.save_contact(contact)
        console.print(f"[green]Paired with {contact.name}[/green]")
        return

    state = RendezvousState(invite=bundle, identity=identity, inviter_profile=inviter_profile)
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
    if bundle.rendezvous_hint == OFFLINE_RENDEZVOUS_HINT:
        console.print("[red]Offline invite — use: yakr invite offline joiner-start <invite-url>[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Safety code:[/green] {safety_code(bundle)}")

    request, secrets = build_pairing_request(
        identity,
        bundle,
        joiner_name=identity.name,
        joiner_profile=_joiner_profile_bytes(store, identity),
    )
    encoded_request = base64.urlsafe_b64encode(request.to_bytes()).decode("ascii").rstrip("=")
    base = bundle.rendezvous_hint.rstrip("/")
    response = httpx.post(
        f"{base}/v1/pair",
        json={"request": encoded_request},
        timeout=10.0,
    )
    if response.status_code not in (200, 202):
        console.print(f"[red]Pairing failed: {response.status_code} {response.text}[/red]")
        raise typer.Exit(code=1)

    payload = response.json()
    if "response" in payload:
        pairing_response = PairingResponse.from_bytes(
            base64.urlsafe_b64decode(str(payload["response"]) + "==")
        )
    else:
        from yakr_cli.relay_pairing import poll_relay_pair_response

        invite_tag = str(payload["invite_tag"])
        console.print(f"[yellow]Waiting for inviter on relay ({invite_tag[:16]}…)…[/yellow]")
        pairing_response = poll_relay_pair_response(base, invite_tag, timeout_secs=120.0)
    contact = joiner_complete_pairing(identity, bundle, request, secrets, pairing_response)
    contact.name = name or bundle.inviter_name
    store.save_contact(contact)
    from yakr_core.capability_client import try_provision_pairing_capabilities

    try_provision_pairing_capabilities(store, identity, contact)
    console.print(f"[green]Paired with {contact.name}[/green]")


def _joiner_profile_bytes(store: FileLocalStore, identity: Identity) -> bytes:
    profile = store.load_local_profile()
    if profile is None:
        profile = build_local_profile(identity, store=store)
        store.save_local_profile(profile)
    return profile.to_bytes()
