from __future__ import annotations

import socket

from yakr_core.http_client import yakr_get


def local_lan_ip() -> str | None:
    """Best-effort LAN IPv4 address for dialability checks (ADR 008)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
    except OSError:
        return None
    if ip.startswith("127."):
        return None
    return ip


def verify_dialable_url(
    url: str,
    *,
    tls_spki: bytes | None = None,
    timeout: float = 2.0,
) -> bool:
    """Return True when remote peers can reach the relay health endpoint."""
    try:
        response = yakr_get(
            f"{url.rstrip('/')}/healthz",
            explicit_pin=tls_spki,
            timeout=timeout,
        )
        return response.status_code == 200
    except Exception:
        return False
