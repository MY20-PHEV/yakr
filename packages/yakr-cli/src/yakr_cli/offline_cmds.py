from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from yakr_core.invite import invite_from_url, safety_code, verify_invite
from yakr_core.pairing import (
    OFFLINE_RENDEZVOUS_HINT,
    build_offline_pairing_request,
    finish_offline_pairing,
    pair_request_from_url,
    pending_session_from_request,
    respond_to_pair_request,
)
from yakr_cli.profile_cmds import build_local_profile

console = Console()
offline_app = typer.Typer(help="In-person QR pairing without network")


def _store():
    from yakr_cli.main import _store

    return _store()


def _require_identity(store):
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def _joiner_profile_bytes(store, identity) -> bytes:
    profile = store.load_local_profile()
    if profile is None:
        profile = build_local_profile(identity, store=store)
        store.save_local_profile(profile)
    return profile.to_bytes()


def _load_invite_url(value: str) -> str:
    if value.startswith("yakr://"):
        return value
    return Path(value).read_text(encoding="utf-8").strip()


def _write_qr(url: str, output: Path | None) -> None:
    if output is None:
        return
    from yakr_cli.qr_util import url_to_qr_png

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(url_to_qr_png(url))
    console.print(f"[cyan]QR PNG:[/cyan] {output}")


@offline_app.command("joiner-start")
def joiner_start(
    invite: str = typer.Argument(..., help="yakr://invite/... URL or invite file"),
    qr_out: Path | None = typer.Option(None, "--qr-out", help="Write pair-request QR PNG"),
) -> None:
    """Scan invite QR, then show pair-request QR for the inviter."""
    store = _store()
    identity = _require_identity(store)
    invite_url = _load_invite_url(invite)
    bundle = invite_from_url(invite_url)
    verify_invite(bundle)
    console.print(f"[green]Safety code:[/green] {safety_code(bundle)} — confirm with inviter")

    request, secrets, request_url = build_offline_pairing_request(
        identity,
        bundle,
        joiner_name=identity.name,
        joiner_profile=_joiner_profile_bytes(store, identity),
    )
    session = pending_session_from_request(invite_url, request, secrets)
    store.save_pending_pairing(session)

    console.print("[green]Show this pair-request QR to the inviter:[/green]")
    console.print(request_url)
    _write_qr(request_url, qr_out)


@offline_app.command("inviter-respond")
def inviter_respond(
    request_url: str = typer.Argument(..., help="yakr://pair-request/... from joiner QR"),
    invite_file: Path | None = typer.Option(
        None,
        "--invite-file",
        help="Invite URL file saved from invite create --offline",
    ),
    qr_out: Path | None = typer.Option(None, "--qr-out", help="Write pair-response QR PNG"),
) -> None:
    """Scan joiner pair-request QR, then show pair-response QR."""
    store = _store()
    identity = _require_identity(store)
    if invite_file is None:
        invite_file = store.root / "invites" / "latest.url"
    if not invite_file.exists():
        console.print("[red]Missing invite file; pass --invite-file or run invite create --offline[/red]")
        raise typer.Exit(code=1)

    invite_url = invite_file.read_text(encoding="utf-8").strip()
    bundle = invite_from_url(invite_url)
    request = pair_request_from_url(request_url)

    local_profile = store.load_local_profile()
    if local_profile is None:
        local_profile = build_local_profile(identity, store=store)
        store.save_local_profile(local_profile)

    _, contact, response_url = respond_to_pair_request(
        identity,
        bundle,
        request,
        inviter_profile=local_profile.to_bytes(),
    )
    store.save_contact(contact)

    console.print(f"[green]Paired with {contact.name}[/green]")
    console.print("[green]Show this pair-response QR to the joiner:[/green]")
    console.print(response_url)
    _write_qr(response_url, qr_out)


@offline_app.command("joiner-finish")
def joiner_finish(
    response_url: str = typer.Argument(..., help="yakr://pair-response/... from inviter QR"),
    name: str | None = typer.Option(None, "--name", "-n", help="Contact name for inviter"),
) -> None:
    """Scan inviter pair-response QR and complete pairing."""
    store = _store()
    identity = _require_identity(store)
    session = store.load_pending_pairing()
    if session is None:
        console.print("[red]No pending offline pairing; run offline joiner-start first[/red]")
        raise typer.Exit(code=1)

    bundle = invite_from_url(session.invite_url)
    request = pair_request_from_url(session.request_url)
    contact = finish_offline_pairing(
        identity,
        bundle,
        request,
        session.secrets(),
        response_url,
        contact_name=name,
    )
    store.save_contact(contact)
    store.clear_pending_pairing()
    console.print(f"[green]Paired with {contact.name}[/green]")
