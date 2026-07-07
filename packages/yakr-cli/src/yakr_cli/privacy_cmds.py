from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from yakr_core.privacy import PrivacyConfig, PrivacyMode

console = Console()
privacy_app = typer.Typer(help="Privacy mode and metadata hardening")


def _store():
    from yakr_cli.main import _store

    return _store()


PRIVACY_COSTS = {
    "fast": {
        "padding": "none",
        "fetch_multiplier": "1×",
        "relay_delay": "0s",
        "battery": "baseline",
        "bandwidth": "baseline",
    },
    "balanced": {
        "padding": "4 KiB classes",
        "fetch_multiplier": "~4× (3 decoy tags)",
        "relay_delay": "0–15s",
        "battery": "~1.3× fetch cost",
        "bandwidth": "~4× fetch + padding overhead",
    },
    "high": {
        "padding": "4/32 KiB classes",
        "fetch_multiplier": "~8× (7 decoy tags)",
        "relay_delay": "5–90s",
        "battery": "~2× fetch + dummy traffic",
        "bandwidth": "~8× fetch + larger padding",
    },
}


@privacy_app.command("set")
def privacy_set(
    contact_name: str = typer.Argument(..., help="Contact to configure"),
    mode: PrivacyMode = typer.Option("balanced", "--mode", "-m", help="fast, balanced, or high"),
) -> None:
    """Set the privacy mode for a contact."""
    store = _store()
    contact = store.get_contact(contact_name)
    if contact is None:
        console.print(f"[red]Unknown contact: {contact_name}[/red]")
        raise typer.Exit(code=1)
    contact.privacy_mode = mode
    store.save_contact(contact)
    config = PrivacyConfig.for_mode(mode)
    console.print(
        f"[green]Set {contact_name} privacy mode to {mode}[/green] "
        f"(relay delay up to {config.relay_delay_max_secs}s)"
    )


@privacy_app.command("show")
def privacy_show(
    contact_name: str | None = typer.Argument(None, help="Contact name or global default"),
) -> None:
    """Show privacy mode for a contact."""
    store = _store()
    if contact_name is None:
        console.print("[yellow]Provide a contact name[/yellow]")
        raise typer.Exit(code=1)
    contact = store.get_contact(contact_name)
    if contact is None:
        console.print(f"[red]Unknown contact: {contact_name}[/red]")
        raise typer.Exit(code=1)
    console.print(f"{contact_name}: {contact.privacy_mode}")


@privacy_app.command("metrics")
def privacy_metrics_cmd() -> None:
    """Show client-side privacy/bandwidth tradeoff stats."""
    store = _store()
    metrics = store.load_privacy_metrics()
    table = Table(title="Privacy Metrics")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("bytes_sent", str(metrics.bytes_sent))
    table.add_row("bytes_fetched", str(metrics.bytes_fetched))
    table.add_row("padding_bytes", str(metrics.padding_bytes))
    table.add_row("decoy_fetches", str(metrics.decoy_fetches))
    table.add_row("dummy_blobs_sent", str(metrics.dummy_blobs_sent))
    table.add_row("send_count", str(metrics.send_count))
    table.add_row("fetch_count", str(metrics.fetch_count))
    console.print(table)


@privacy_app.command("costs")
def privacy_costs_cmd() -> None:
    """Document battery and bandwidth tradeoffs per privacy mode."""
    table = Table(title="Privacy Mode Costs")
    table.add_column("Mode")
    table.add_column("Padding")
    table.add_column("Fetch")
    table.add_column("Relay delay")
    table.add_column("Battery")
    table.add_column("Bandwidth")
    for mode, costs in PRIVACY_COSTS.items():
        table.add_row(
            mode,
            costs["padding"],
            costs["fetch_multiplier"],
            costs["relay_delay"],
            costs["battery"],
            costs["bandwidth"],
        )
    console.print(table)
