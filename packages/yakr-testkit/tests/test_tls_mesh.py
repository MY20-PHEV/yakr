from __future__ import annotations

from pathlib import Path

import pytest

from yakr_core.tls import endpoint_tls_spki_sha256
from yakr_testkit.mesh_setup import build_charlie_mesh, run_mesh_stress


def test_mesh_profiles_include_tls_pins(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        for name, participant in (
            ("alice", mesh.alice),
            ("bob", mesh.bob),
            ("charlie", mesh.charlie),
            ("dennis", mesh.dennis),
        ):
            profile = participant.store.load_local_profile()
            assert profile is not None, f"{name} missing profile"
            assert profile.endpoint_tls_spki_sha256
            assert profile.endpoint_tls_spki_sha256 == endpoint_tls_spki_sha256(participant.identity)
            for relay in profile.relay_descriptors:
                assert relay.url.startswith("https://"), relay.url
                if relay.name in {"charlie", "dennis"}:
                    assert relay.tls_spki_sha256

        charlie_contact = mesh.alice.store.get_contact("charlie")
        assert charlie_contact is not None
        assert charlie_contact.delivery_profile is not None
        assert (
            charlie_contact.delivery_profile.endpoint_tls_spki_sha256
            == mesh.charlie_relay.tls_spki_sha256
        )
    finally:
        mesh.stop()


def test_mesh_stress_over_tls(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        result = run_mesh_stress(mesh)
        assert result["total_sent"] >= 100
        assert result["missing"] == []
        assert result["duplicate_fetch_hits"] == 0
        assert result["pending_after"] == 0
    finally:
        mesh.stop()


def test_bob_resolves_dennis_tls_pin_from_alice_profile_only(tmp_path: Path) -> None:
    """Bob need not pair with Dennis to verify Dennis when using Alice's relay list."""
    from yakr_core.http_client import resolve_tls_pin_for_url

    mesh = build_charlie_mesh(tmp_path)
    try:
        assert mesh.bob.store.get_contact("dennis") is None
        alice = mesh.bob.store.get_contact("alice")
        assert alice is not None and alice.delivery_profile is not None
        dennis_url = mesh.dennis_relay.relay_url
        for descriptor in alice.delivery_profile.relay_descriptors:
            if descriptor.name == "dennis":
                assert descriptor.tls_spki_sha256 == mesh.dennis_relay.tls_spki_sha256
                break
        else:
            raise AssertionError("alice profile missing dennis relay descriptor")
        pin = resolve_tls_pin_for_url(
            f"{dennis_url}/v1/blobs",
            store=mesh.bob.store,
            contact=alice,
        )
        assert pin == mesh.dennis_relay.tls_spki_sha256
    finally:
        mesh.stop()


def test_tls_rejects_wrong_pin(tmp_path: Path) -> None:
    from yakr_core.http_client import yakr_get

    mesh = build_charlie_mesh(tmp_path)
    try:
        wrong_pin = b"\x01" * 32
        with pytest.raises(Exception):
            yakr_get(
                f"{mesh.charlie_relay.relay_url}/healthz",
                explicit_pin=wrong_pin,
                timeout=2.0,
            )
    finally:
        mesh.stop()
