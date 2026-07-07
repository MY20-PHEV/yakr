from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from yakr_core.invite import invite_from_url, verify_invite
from yakr_cli.relay_pairing import inviter_wait_on_relay

console = Console()
relay_app = typer.Typer(help="Group relay pairing")


@relay_app.command("wait")
def relay_wait(
    invite_file: Path | None = typer.Option(
        None,
        "--invite-file",
        help="Invite URL file (default: latest invite in store)",
    ),
) -> None:
    """Wait for a joiner via group relay rendezvous and complete pairing."""
    from yakr_cli.main import _require_identity, _store

    store = _store()
    identity = _require_identity(store)
    invite_path = invite_file or (store.root / "invites" / "latest.url")
    if not invite_path.exists():
        console.print("[red]No invite file found[/red]")
        raise typer.Exit(code=1)

    bundle = invite_from_url(invite_path.read_text(encoding="utf-8").strip())
    verify_invite(bundle)
    profile = store.load_local_profile()
    inviter_profile = profile.to_bytes() if profile else b""

    console.print(f"[yellow]Waiting on relay {bundle.rendezvous_hint}…[/yellow]")
    _, contact = inviter_wait_on_relay(
        bundle.rendezvous_hint,
        identity,
        bundle,
        inviter_profile=inviter_profile,
        timeout_secs=120.0,
    )
    store.save_contact(contact)
    console.print(f"[green]Paired with {contact.name}[/green]")
