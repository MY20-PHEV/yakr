from __future__ import annotations

import argparse
from pathlib import Path

import uvicorn

from yakr_relay.app import create_app
from yakr_relay.store import BlobStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Yakr relay daemon")
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default="/data")
    args = parser.parse_args()

    if args.command == "serve":
        store = BlobStore(Path(args.data_dir))
        app = create_app(store)
        uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
