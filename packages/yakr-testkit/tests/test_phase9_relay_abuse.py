from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def client(tmp_path):
    store = BlobStore(tmp_path / "relay", max_blobs_per_tag=3)
    app = create_app(store, RelayRuntime(role="mailbox", wrap_secret=None, name="test"))
    with TestClient(app) as test_client:
        yield test_client, store


def _store_payload(tag: bytes, *, expires_at: int | None = None, ciphertext: bytes = b"x") -> dict:
    import base64

    now = int(time.time() * 1000)
    return {
        "mailbox_tag": base64.urlsafe_b64encode(tag).decode("ascii").rstrip("="),
        "expires_at": expires_at or (now + 60_000),
        "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii").rstrip("="),
    }


def test_relay_rejects_short_mailbox_tag(client) -> None:
    test_client, _ = client
    payload = _store_payload(b"short")
    response = test_client.post("/v1/blobs", json=payload)
    assert response.status_code == 400
    assert "32 bytes" in response.json()["detail"]


def test_relay_rejects_expired_blob(client) -> None:
    test_client, _ = client
    tag = b"\x01" * 32
    payload = _store_payload(tag, expires_at=int(time.time() * 1000) - 1)
    response = test_client.post("/v1/blobs", json=payload)
    assert response.status_code == 400
    assert "expired" in response.json()["detail"]


def test_relay_rejects_oversized_blob(client) -> None:
    test_client, _ = client
    tag = b"\x02" * 32
    payload = _store_payload(tag, ciphertext=b"x" * (64 * 1024 + 1))
    response = test_client.post("/v1/blobs", json=payload)
    assert response.status_code == 400
    assert "large" in response.json()["detail"]


def test_relay_enforces_per_tag_blob_cap(client) -> None:
    test_client, _ = client
    tag = b"\x03" * 32
    for _ in range(3):
        response = test_client.post("/v1/blobs", json=_store_payload(tag))
        assert response.status_code == 201

    response = test_client.post("/v1/blobs", json=_store_payload(tag))
    assert response.status_code == 429
    assert "limit" in response.json()["detail"]


def test_relay_fetch_returns_only_non_expired(client) -> None:
    test_client, _ = client
    tag = b"\x04" * 32
    import base64

    tag_b64 = base64.urlsafe_b64encode(tag).decode("ascii").rstrip("=")
    now = int(time.time() * 1000)
    test_client.post(
        "/v1/blobs",
        json={
            "mailbox_tag": tag_b64,
            "expires_at": now + 120_000,
            "ciphertext": base64.urlsafe_b64encode(b"alive").decode("ascii").rstrip("="),
        },
    )
    test_client.post(
        "/v1/blobs",
        json={
            "mailbox_tag": tag_b64,
            "expires_at": now - 1,
            "ciphertext": base64.urlsafe_b64encode(b"dead").decode("ascii").rstrip("="),
        },
        # expired at store time — should be rejected
    )
    # second post fails at store; store only valid one
    blobs = test_client.get(f"/v1/blobs/{tag_b64}").json()
    assert len(blobs) == 1
    assert blobs[0]["ciphertext"] == base64.urlsafe_b64encode(b"alive").decode("ascii").rstrip("=")
