"""Homelab integration tests against real Charlie + Dennis relays."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yakr_core.http_client import resolve_tls_pin_for_url
from yakr_testkit.homelab_mesh import (
    assert_vps_trust_model,
    build_homelab_mesh,
    homelab_env_configured,
)


pytestmark = pytest.mark.homelab


@pytest.fixture
def homelab_mesh(tmp_path: Path):
    if not homelab_env_configured():
        pytest.skip("set CHARLIE_URL and DENNIS_URL for homelab tests")
    previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
    previous_name = os.environ.pop("YAKR_RELAY_NAME", None)
    mesh = build_homelab_mesh(tmp_path)
    try:
        yield mesh
    finally:
        mesh.stop()
        if previous_relay is None:
            os.environ.pop("YAKR_RELAY_URL", None)
        else:
            os.environ["YAKR_RELAY_URL"] = previous_relay
        if previous_name is None:
            os.environ.pop("YAKR_RELAY_NAME", None)
        else:
            os.environ["YAKR_RELAY_NAME"] = previous_name


def test_homelab_vps_trust_model(homelab_mesh) -> None:
    mesh = homelab_mesh
    assert_vps_trust_model(mesh)


def test_homelab_bob_resolves_relay_pins_from_alice_only(homelab_mesh) -> None:
    mesh = homelab_mesh
    alice = mesh.bob.store.get_contact("alice")
    assert alice is not None and alice.delivery_profile is not None

    charlie_pin = resolve_tls_pin_for_url(
        f"{mesh.charlie_relay.relay_url}/healthz",
        store=mesh.bob.store,
        contact=alice,
    )
    dennis_pin = resolve_tls_pin_for_url(
        f"{mesh.dennis_relay.relay_url}/healthz",
        store=mesh.bob.store,
        contact=alice,
    )
    assert charlie_pin == mesh.charlie_relay.tls_spki_sha256
    assert dennis_pin == mesh.dennis_relay.tls_spki_sha256


def test_homelab_alice_bob_messaging(homelab_mesh) -> None:
    mesh = homelab_mesh
    mesh.alice.send("bob", "homelab hello")
    got = mesh.bob.fetch("alice", send_receipts=True)
    assert [m.body for m in got] == ["homelab hello"]
    mesh.alice.drain_receipts()

    mesh.bob.send("alice", "homelab reply")
    reply = mesh.alice.fetch("bob", send_receipts=True)
    assert [m.body for m in reply] == ["homelab reply"]


def test_homelab_failover_to_dennis_when_charlie_down(homelab_mesh) -> None:
    mesh = homelab_mesh
    if not mesh.charlie_relay.vps_host:
        pytest.skip("set CHARLIE_VPS_HOST or VPS_HOST for relay stop/start")

    mesh.stop_relay()
    try:
        record, err = mesh.alice.try_send("bob", "homelab dennis failover")
        assert err is None
        assert record is not None
        got = mesh.bob.fetch("alice", send_receipts=True)
        assert [m.body for m in got] == ["homelab dennis failover"]
    finally:
        mesh.start_relay()
