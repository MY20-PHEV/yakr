"""Deploy a relay operator bundle to a remote VPS (homelab)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from yakr_core.identity import b64encode
from yakr_core.relay_operator import load_relay_operator_manifest, relay_operator_home
from yakr_core.store import FileLocalStore


def repo_root_from_here(here: Path) -> Path:
    """Repository root when called from packages/yakr-cli or yakr-testkit."""
    resolved = here.resolve()
    for parent in resolved.parents:
        if (parent / "scripts" / "deploy_charlie_vps.sh").exists():
            return parent
    raise FileNotFoundError("could not locate repository root (deploy_charlie_vps.sh)")


def deploy_operator_bundle(
    owner_store: FileLocalStore,
    operator_name: str,
    vps_host: str,
    *,
    repo_root: Path | None = None,
    host_port: int | None = None,
) -> Path:
    """Run scripts/deploy_charlie_vps.sh for an operator under owner_store/relays/<name>."""
    operator_home = relay_operator_home(owner_store.root, operator_name)
    manifest = load_relay_operator_manifest(operator_home)
    tls_dir = operator_home / "relay-tls"
    if not (tls_dir / "endpoint.key.pem").exists():
        raise FileNotFoundError(f"missing TLS material under {tls_dir}")

    root = repo_root or repo_root_from_here(Path(__file__))
    script = root / "scripts" / "deploy_charlie_vps.sh"
    if not script.exists():
        raise FileNotFoundError(f"deploy script not found: {script}")

    port = host_port if host_port is not None else manifest.host_port
    remote_dir = f"~/yakr-relay-{manifest.operator_name}"
    env = os.environ.copy()
    env.update(
        {
            "VPS_HOST": vps_host,
            "CHARLIE_PORT": str(port),
            "CHARLIE_WRAP_SECRET": b64encode(manifest.wrap_secret),
            "CHARLIE_TLS_DIR": str(tls_dir),
            "REMOTE_DIR": remote_dir,
            "RELAY_NAME": manifest.operator_name,
            "RELAY_CONTAINER": f"yakr-{manifest.operator_name}",
            "RELAY_DATA_VOLUME": f"yakr-{manifest.operator_name}-data",
            "URL_EXPORT_NAME": f"{manifest.operator_name.upper().replace('-', '_')}_URL",
        }
    )
    subprocess.run(["bash", str(script)], cwd=root, env=env, check=True)
    return operator_home


def resolve_alice_ops_vps_host() -> str | None:
    return (
        os.environ.get("ALICE_OPS_VPS_HOST", "").strip()
        or os.environ.get("VPS_HOST", "").strip()
        or os.environ.get("CHARLIE_VPS_HOST", "").strip()
        or os.environ.get("DENNIS_VPS_HOST", "").strip()
        or None
    )


def resolve_alice_ops_public_url(*, host_port: int | None = None) -> str:
    explicit = os.environ.get("ALICE_OPS_URL", "").strip().rstrip("/")
    if explicit:
        return explicit
    charlie = os.environ.get("CHARLIE_URL", "").strip().rstrip("/")
    if not charlie:
        raise ValueError("set ALICE_OPS_URL or CHARLIE_URL to derive homelab host")
    from urllib.parse import urlparse

    parsed = urlparse(charlie)
    if not parsed.hostname:
        raise ValueError(f"cannot parse host from CHARLIE_URL={charlie!r}")
    port = host_port if host_port is not None else int(os.environ.get("ALICE_OPS_PORT", "8092"))
    scheme = parsed.scheme or "https"
    return f"{scheme}://{parsed.hostname}:{port}"
