from __future__ import annotations

import argparse
import base64
import threading
import time
from pathlib import Path

import uvicorn
from cryptography.hazmat.primitives.asymmetric import ed25519

from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore


def _parse_wrap_secret(value: str | None) -> bytes | None:
    if value is None:
        return None
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _load_fixed_bytes(value: str, *, expected_len: int) -> bytes:
    path = Path(value)
    if path.exists():
        raw = path.read_bytes()
    else:
        raw = bytes.fromhex(value.strip())
    if len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} bytes, got {len(raw)}")
    return raw


def main() -> None:
    parser = argparse.ArgumentParser(description="Yakr relay daemon")
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default="/data")
    parser.add_argument("--role", choices=["entry", "mailbox", "both"], default="mailbox")
    parser.add_argument("--name", default="relay")
    parser.add_argument("--wrap-secret", default=None)
    parser.add_argument("--require-tickets", action="store_true")
    parser.add_argument("--require-capabilities", action="store_true")
    parser.add_argument(
        "--relay-issuance-private-key",
        default=None,
        help="Path to 32-byte relay capability issuance private key",
    )
    parser.add_argument(
        "--relay-tls-spki-sha256",
        default=None,
        help="Operator TLS SPKI pin as hex string or path to .hex file",
    )
    parser.add_argument("--forward-delay-max", type=int, default=0, help="Max random forward delay seconds")
    parser.add_argument("--ssl-keyfile", default=None, help="TLS private key PEM (HTTPS)")
    parser.add_argument("--ssl-certfile", default=None, help="TLS certificate PEM (HTTPS)")
    args = parser.parse_args()

    if args.command == "serve":
        data_dir = Path(args.data_dir)
        store = BlobStore(data_dir)
        pairing_store = PairingStore(data_dir)
        relay_issuance_private = b""
        relay_issuance_public = b""
        if args.relay_issuance_private_key:
            relay_issuance_private = _load_fixed_bytes(args.relay_issuance_private_key, expected_len=32)
            relay_issuance_public = (
                ed25519.Ed25519PrivateKey.from_private_bytes(relay_issuance_private)
                .public_key()
                .public_bytes_raw()
            )
        relay_tls_spki_sha256 = b""
        if args.relay_tls_spki_sha256:
            relay_tls_spki_sha256 = _load_fixed_bytes(args.relay_tls_spki_sha256, expected_len=32)
        if args.require_capabilities and not relay_issuance_private:
            parser.error("--require-capabilities requires --relay-issuance-private-key")
        if args.require_capabilities and not relay_tls_spki_sha256:
            parser.error("--require-capabilities requires --relay-tls-spki-sha256")
        runtime = RelayRuntime(
            role=args.role,
            wrap_secret=_parse_wrap_secret(args.wrap_secret),
            name=args.name,
            require_tickets=args.require_tickets,
            require_capabilities=args.require_capabilities,
            forward_delay_max_secs=args.forward_delay_max,
            relay_issuance_public=relay_issuance_public,
            relay_issuance_private=relay_issuance_private,
            relay_tls_spki_sha256=relay_tls_spki_sha256,
        )
        app = create_app(store, runtime, pairing_store=pairing_store)

        stop_event = threading.Event()

        @app.on_event("startup")
        def _start_sweeper() -> None:
            def sweeper() -> None:
                while not stop_event.is_set():
                    store.sweep_expired()
                    pairing_store.sweep_expired()
                    stop_event.wait(60)

            thread = threading.Thread(target=sweeper, daemon=True)
            thread.start()

        @app.on_event("shutdown")
        def _stop_sweeper() -> None:
            stop_event.set()

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info",
            ssl_keyfile=args.ssl_keyfile,
            ssl_certfile=args.ssl_certfile,
        )


if __name__ == "__main__":
    main()
