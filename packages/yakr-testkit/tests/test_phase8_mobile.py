from __future__ import annotations

import base64
import secrets
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from yakr_core.identity import Identity, export_public_bundle
from yakr_core.invite import create_invite, invite_to_url
from yakr_core.pairing import (
    build_pairing_request,
    inviter_complete_pairing,
    joiner_complete_pairing,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from yakr_core.store import FileLocalStore
from yakr_mobile.client import FetchWorker, RelayWorker, YakrMobileClient
from yakr_mobile.device_settings import DeviceSettings
from yakr_mobile.encrypted_store import MobileStore
from yakr_mobile.invite_qr import build_invite_presentation
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


@pytest.fixture
def mobile_relay(tmp_path: Path):
    store = BlobStore(tmp_path / "relay")
    app = create_app(store, RelayRuntime(role="mailbox", wrap_secret=None, name="relay"))
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    yield url
    server.should_exit = True

def _mobile_client(tmp_path: Path, relay_url: str, name: str) -> YakrMobileClient:
    store = MobileStore(tmp_path / f"{name}.db", passphrase="test-passphrase")
    client = YakrMobileClient(store, relay_url=relay_url)
    client.init_identity(name)
    return client


def test_encrypted_store_roundtrip(tmp_path) -> None:
    store = MobileStore(tmp_path / "device.db", passphrase="secret")
    alice = Identity.generate("alice")
    store.save_identity(alice)
    reloaded = store.load_identity()
    assert reloaded is not None
    assert reloaded.name == "alice"


def test_invite_qr_payload(tmp_path) -> None:
    alice = Identity.generate("alice")
    presentation = build_invite_presentation(alice, rendezvous_hint="http://127.0.0.1:8090")
    assert presentation.url.startswith("yakr://invite/")
    assert len(presentation.qr_png) > 100
    assert len(presentation.safety.split()) == 3


def test_offline_delivery_between_mobile_clients(mobile_relay, tmp_path) -> None:
    alice_client = _mobile_client(tmp_path / "alice", mobile_relay, "alice")
    bob_client = _mobile_client(tmp_path / "bob", mobile_relay, "bob")

    alice = alice_client.load_identity()
    bob = bob_client.load_identity()
    assert alice is not None and bob is not None

    invite = create_invite(alice, rendezvous_hint="http://test")
    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)

    from yakr_core.identity import Contact

    alice_client.store.save_contact(alice_contact)
    bob_client.store.save_contact(bob_contact)

    alice_client.send_text("bob", "mobile hello")
    fetched = bob_client.fetch_contact("alice")
    assert fetched.messages == ["mobile hello"]


def test_fetch_worker_respects_battery_intervals(tmp_path) -> None:
    settings = DeviceSettings(charging=False, battery_percent=100)
    store = MobileStore(tmp_path / "worker.db", passphrase="pw")
    worker = FetchWorker(YakrMobileClient(store, relay_url="http://127.0.0.1:1"), settings)
    assert worker.poll_interval_secs == 300
    settings_low = DeviceSettings(charging=False, battery_percent=10)
    store_low = MobileStore(tmp_path / "worker-low.db", passphrase="pw")
    worker_low = FetchWorker(YakrMobileClient(store_low, relay_url="http://127.0.0.1:1"), settings_low)
    assert worker_low.poll_interval_secs == 900


def test_relay_worker_wifi_charging_gates() -> None:
    worker = RelayWorker(DeviceSettings(relay_enabled=True, on_wifi=False, relay_wifi_only=True))
    assert worker.should_run() is False
    worker_ok = RelayWorker(DeviceSettings(relay_enabled=True, on_wifi=True, charging=True))
    assert worker_ok.should_run() is True


def test_process_death_resume_state(mobile_relay, tmp_path) -> None:
    client = _mobile_client(tmp_path / "resume", mobile_relay, "alice")
    bob = Identity.generate("bob")
    from yakr_core.identity import Contact

    contact = Contact.establish(client.load_identity(), "bob", export_public_bundle(bob))
    client.store.save_contact(contact)
    client.send_text("bob", "persist me")
    client.store.save_worker_state("last_fetch_at", "123")

    reloaded_store = MobileStore(tmp_path / "resume" / "alice.db", passphrase="test-passphrase")
    resumed = YakrMobileClient(reloaded_store, relay_url=mobile_relay)
    state = resumed.resume_state()
    assert state["last_fetch_at"] == "123"
    assert "bob" in state["pending"] or resumed.store.list_outbound_pending("bob")
