from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path

import typer
import uvicorn
from rich.console import Console

from yakr_core.identity import Identity
from yakr_core.presence import PresencePayload
from yakr_core.reachability import local_lan_ip, verify_dialable_url
from yakr_core.tls import endpoint_tls_spki_sha256, write_endpoint_tls_files
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore
from yakr_cli.presence_cmds import broadcast_presence
from yakr_cli import relay_create_cmds

console = Console()
relay_ops_app = typer.Typer(help="Relay operator commands")

relay_ops_app.command("create")(relay_create_cmds.relay_create)
relay_ops_app.command("deploy")(relay_create_cmds.relay_deploy)
relay_ops_app.command("status")(relay_create_cmds.relay_status)


def _store():
    from yakr_cli.main import _store

    return _store()


def _require_identity(store) -> Identity:
    from yakr_cli.main import _require_identity

    return _require_identity(store)


def _reachable_embed_url(host: str, port: int, lan_ip: str | None) -> tuple[str, bool]:
    """Build candidate reachable URL and whether it may be remote-dialable (ADR 008)."""
    if host in {"0.0.0.0", "::"} and lan_ip:
        return f"https://{lan_ip}:{port}", True
    if host not in {"127.0.0.1", "localhost", "::1"}:
        return f"https://{host}:{port}", True
    return f"https://127.0.0.1:{port}", False


@relay_ops_app.command("embed")
def relay_embed(
    host: str = typer.Option("0.0.0.0", "--host", help="Bind address"),
    port: int = typer.Option(8090, "--port", "-p", help="Listen port"),
    push_presence: bool = typer.Option(
        True,
        "--push-presence/--no-push-presence",
        help="Fan out presence when relay is dialable",
    ),
) -> None:
    """Run an embedded relay when this host is dialable (LAN / public IP — ADR 008)."""
    store = _store()
    identity = _require_identity(store)
    relay_dir = store.root / "relay-embed"
    relay_dir.mkdir(parents=True, exist_ok=True)
    wrap_secret = secrets.token_bytes(32)
    blob_store = BlobStore(relay_dir / "blobs")
    pairing_store = PairingStore(relay_dir / "pairing")
    runtime = RelayRuntime(role="both", wrap_secret=wrap_secret, name=identity.name)
    app = create_app(blob_store, runtime, pairing_store=pairing_store)
    keyfile, certfile = write_endpoint_tls_files(identity, relay_dir / "tls")
    tls_spki = endpoint_tls_spki_sha256(identity)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        ssl_keyfile=str(keyfile),
        ssl_certfile=str(certfile),
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        console.print("[red]Embedded relay failed to start[/red]")
        raise typer.Exit(code=1)

    lan_ip = local_lan_ip()
    reachable_url, may_be_remote = _reachable_embed_url(host, port, lan_ip)
    dialable = False
    if may_be_remote:
        dialable = verify_dialable_url(reachable_url, tls_spki=tls_spki)
    elif verify_dialable_url(reachable_url, tls_spki=tls_spki):
        dialable = True

    relay_active = dialable and may_be_remote
    console.print(f"[green]Embedded relay listening on {host}:{port}[/green]")
    console.print(f"[cyan]Reachable URL:[/cyan] {reachable_url}")
    console.print(f"[cyan]Remote dialable:[/cyan] {relay_active}")

    if not relay_active:
        console.print(
            "[yellow]Not advertising relay.active=true — bind a LAN/public address "
            "or verify dialability before remote peers can POST[/yellow]"
        )

    if push_presence:
        payload = PresencePayload.for_operator(
            identity.name,
            reachable_url,
            relay_active=relay_active,
        )
        pushed = broadcast_presence(store, identity, [payload], quiet=False)
        if pushed == 0:
            console.print("[yellow]Presence not delivered (no paired contacts yet?)[/yellow]")

    console.print("[dim]Press Ctrl+C to stop embedded relay[/dim]")
    try:
        while server.started:
            time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("[yellow]Stopping embedded relay…[/yellow]")
        server.should_exit = True
        thread.join(timeout=5)
