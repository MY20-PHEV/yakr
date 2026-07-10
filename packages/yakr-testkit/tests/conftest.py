from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture(autouse=True)
def _default_tls_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Legacy unit tests may use plain HTTP relays unless they opt into TLS."""
    if "YAKR_REQUIRE_TLS" not in os.environ:
        monkeypatch.setenv("YAKR_REQUIRE_TLS", "0")


@pytest.fixture
def relay_server(tmp_path: Path) -> str:
    """Ephemeral HTTP relay for lightweight delivery roundtrip tests."""
    wrap_secret = secrets.token_bytes(32)
    blob_store = BlobStore(tmp_path / "relay-data")
    app = create_app(
        blob_store,
        RelayRuntime(role="both", wrap_secret=wrap_secret, name="test-relay"),
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("relay fixture failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    try:
        yield url
    finally:
        server.should_exit = True
        thread.join(timeout=5)
