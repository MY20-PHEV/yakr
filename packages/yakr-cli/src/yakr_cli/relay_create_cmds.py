from __future__ import annotations

import os
import subprocess
from pathlib import Path

import httpx
import typer
from rich.console import Console

from yakr_core.http_client import yakr_get
from yakr_core.identity import b64encode
from yakr_core.relay_authorization import authorized_publish_relays
from yakr_core.relay_deploy import deploy_operator_bundle, repo_root_from_here
from yakr_core.relay_operator import (
    create_relay_operator,
    load_relay_operator_manifest,
    relay_operator_home,
)
from yakr_core.store import FileLocalStore
from yakr_core.tls import endpoint_tls_spki_sha256

console = Console()


def _store() -> FileLocalStore:
    from yakr_cli.main import _store

    return _store()


def _require_identity(store: FileLocalStore):
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def _repo_root() -> Path:
    return repo_root_from_here(Path(__file__))


def relay_create(
    operator_name: str = typer.Argument(..., help="Dedicated relay operator name (e.g. alice-ops)"),
    public_url: str = typer.Option(
        ...,
        "--public-url",
        help="Planned HTTPS URL peers will use (e.g. https://relay.example:8090)",
    ),
    host_port: int = typer.Option(8090, "--port", "-p", help="Host port for deploy / docker-compose"),
    force: bool = typer.Option(False, "--force", help="Recreate operator bundle if it exists"),
) -> None:
    """Create a relay operator identity pre-paired with your messaging identity."""
    store = _store()
    identity = _require_identity(store)

    try:
        bundle = create_relay_operator(
            store,
            operator_name=operator_name,
            public_url=public_url,
            host_port=host_port,
            force=force,
        )
    except (ValueError, FileExistsError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    operator = bundle.operator_store.load_identity()
    assert operator is not None
    authorized = authorized_publish_relays(
        identity_name=identity.name,
        contacts=[bundle.owner_contact],
    )
    console.print(f"[green]Created relay operator '{operator_name}'[/green]")
    console.print(f"[cyan]Operator home:[/cyan] {bundle.operator_home}")
    console.print(f"[cyan]Public URL:[/cyan] {bundle.manifest.public_url}")
    console.print(f"[cyan]TLS SPKI:[/cyan] {endpoint_tls_spki_sha256(operator).hex()}")
    console.print(f"[cyan]Publishable relays:[/cyan] {len(authorized)} descriptor(s) authorized")
    console.print(
        f"\n[dim]Next: yakr relay deploy {operator_name} --vps user@host "
        "then yakr profile publish && yakr profile push <contact>[/dim]"
    )


def relay_deploy(
    operator_name: str = typer.Argument(..., help="Relay operator created with `yakr relay create`"),
    vps_host: str = typer.Option(..., "--vps", help="SSH target, e.g. user@203.0.113.10"),
) -> None:
    """Deploy operator bundle to a VPS via scripts/deploy_charlie_vps.sh."""
    store = _store()
    _require_identity(store)

    try:
        deploy_operator_bundle(store, operator_name, vps_host, repo_root=_repo_root())
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    except subprocess.CalledProcessError as exc:
        console.print(f"[red]deploy failed (exit {exc.returncode})[/red]")
        raise typer.Exit(code=exc.returncode) from exc

    manifest = load_relay_operator_manifest(relay_operator_home(store.root, operator_name))
    console.print(
        f"[green]Deploy complete.[/green] Run [bold]yakr profile publish[/bold] "
        f"then [bold]yakr profile push[/bold] so contacts learn {manifest.public_url}"
    )


def relay_status(
    operator_name: str = typer.Argument(..., help="Relay operator name"),
) -> None:
    """Check manifest and relay health for an operator bundle."""
    store = _store()
    _require_identity(store)

    operator_home = relay_operator_home(store.root, operator_name)
    try:
        manifest = load_relay_operator_manifest(operator_home)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    operator_store = FileLocalStore(operator_home)
    operator = operator_store.load_identity()
    if operator is None:
        console.print("[red]operator identity missing[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Operator:[/cyan] {manifest.operator_name}")
    console.print(f"[cyan]Owner:[/cyan] {manifest.owner_name}")
    console.print(f"[cyan]URL:[/cyan] {manifest.public_url}")

    try:
        response = yakr_get(
            f"{manifest.public_url}/healthz",
            explicit_pin=endpoint_tls_spki_sha256(operator),
            timeout=5.0,
        )
        if response.status_code == 200:
            console.print("[green]Health: ok[/green]")
        else:
            console.print(f"[yellow]Health: HTTP {response.status_code}[/yellow]")
    except (httpx.HTTPError, OSError) as exc:
        console.print(f"[yellow]Health: unreachable ({exc})[/yellow]")
