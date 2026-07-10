"""Default POST /v1/fetch relay polling."""

from __future__ import annotations

import secrets
import threading
import time

import pytest
import uvicorn

from yakr_cli.network import fetch_relay_blobs
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore, _b64encode


@pytest.fixture
def fetch_relay(tmp_path):
    store = BlobStore(tmp_path / "relay")
    runtime = RelayRuntime(role="mailbox", wrap_secret=None, name="relay")
    app = create_app(store, runtime)
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    yield url, store
    server.should_exit = True
    thread.join(timeout=2)


def test_fetch_relay_blobs_uses_post_fetch_by_default(fetch_relay, monkeypatch) -> None:
    url, store = fetch_relay
    tag = secrets.token_bytes(32)
    store.store(tag, int(time.time() * 1000) + 60_000, b"payload")
    tag_b64 = _b64encode(tag)
    monkeypatch.delenv("YAKR_LEGACY_GET_FETCH", raising=False)

    items = fetch_relay_blobs(tag_b64, [url])
    assert len(items) == 1
    assert items[0]["ciphertext"]


def test_fetch_relay_blobs_legacy_get_opt_in(fetch_relay, monkeypatch) -> None:
    url, store = fetch_relay
    tag = secrets.token_bytes(32)
    store.store(tag, int(time.time() * 1000) + 60_000, b"legacy")
    tag_b64 = _b64encode(tag)
    monkeypatch.setenv("YAKR_LEGACY_GET_FETCH", "1")

    items = fetch_relay_blobs(tag_b64, [url])
    assert len(items) == 1
