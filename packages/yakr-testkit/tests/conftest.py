from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest
import uvicorn

from yakr_relay.app import create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def relay_server(tmp_path: Path):
    store = BlobStore(tmp_path / "relay")
    app = create_app(store)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    port = server.servers[0].sockets[0].getsockname()[1]
    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.should_exit = True
    thread.join(timeout=2)
