from __future__ import annotations

import argparse
import base64
import threading
import time
from pathlib import Path

import uvicorn

from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


def _parse_wrap_secret(value: str | None) -> bytes | None:
    if value is None:
        return None
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def main() -> None:
    parser = argparse.ArgumentParser(description="Yakr relay daemon")
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default="/data")
    parser.add_argument("--role", choices=["entry", "mailbox", "both"], default="mailbox")
    parser.add_argument("--name", default="relay")
    parser.add_argument("--wrap-secret", default=None)
    args = parser.parse_args()

    if args.command == "serve":
        store = BlobStore(Path(args.data_dir))
        runtime = RelayRuntime(
            role=args.role,
            wrap_secret=_parse_wrap_secret(args.wrap_secret),
            name=args.name,
        )
        app = create_app(store, runtime)

        stop_event = threading.Event()

        @app.on_event("startup")
        def _start_sweeper() -> None:
            def sweeper() -> None:
                while not stop_event.is_set():
                    store.sweep_expired()
                    stop_event.wait(60)

            thread = threading.Thread(target=sweeper, daemon=True)
            thread.start()

        @app.on_event("shutdown")
        def _stop_sweeper() -> None:
            stop_event.set()

        uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
