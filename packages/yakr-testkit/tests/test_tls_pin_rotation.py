"""TLS pin rotation without re-pairing (P0-9)."""

from __future__ import annotations

from pathlib import Path

import pytest

from yakr_core.delivery_profile import create_delivery_profile, relay_descriptor_for_operator
from yakr_core.http_client import resolve_tls_pin_for_url, yakr_get
from yakr_core.tls import endpoint_tls_spki_sha256, write_endpoint_tls_files
from yakr_testkit.mesh_setup import build_charlie_mesh


def _rotate_relay_tls(mesh, relay_name: str) -> bytes:
    if relay_name == "charlie":
        handle = mesh.charlie_relay
        identity = mesh.charlie.identity
        store = mesh.charlie.store
        wrap_secret = handle.wrap_secret
    else:
        handle = mesh.dennis_relay
        identity = mesh.dennis.identity
        store = mesh.dennis.store
        wrap_secret = handle.wrap_secret

    identity.tls_ecdsa_private = None
    tls_dir = handle.relay_data_path / "tls"
    keyfile, certfile = write_endpoint_tls_files(identity, tls_dir)
    new_pin = endpoint_tls_spki_sha256(identity)
    handle.ssl_keyfile = keyfile
    handle.ssl_certfile = certfile
    handle.tls_spki_sha256 = new_pin
    handle.stop()
    handle.start()

    old_profile = store.load_local_profile()
    assert old_profile is not None
    descriptor = relay_descriptor_for_operator(
        identity,
        "both",
        handle.relay_url,
        wrap_secret,
        name=relay_name,
    )
    rotated_profile = create_delivery_profile(
        identity,
        relay_descriptors=[descriptor],
        version=old_profile.version + 1,
    )
    store.save_local_profile(rotated_profile)
    return new_pin


def test_tls_pin_rotation_without_repair(tmp_path: Path) -> None:
    mesh = build_charlie_mesh(tmp_path)
    try:
        bob_alice = mesh.bob.store.get_contact("alice")
        assert bob_alice is not None and bob_alice.delivery_profile is not None
        old_pin = mesh.charlie_relay.tls_spki_sha256
        old_bob_pin = resolve_tls_pin_for_url(
            f"{mesh.charlie_relay.relay_url}/healthz",
            store=mesh.bob.store,
            contact=bob_alice,
        )
        assert old_bob_pin == old_pin

        new_pin = _rotate_relay_tls(mesh, "charlie")
        assert new_pin != old_pin

        charlie_profile = mesh.charlie.store.load_local_profile()
        assert charlie_profile is not None
        alice_charlie = mesh.alice.store.get_contact("charlie")
        assert alice_charlie is not None
        alice_charlie.delivery_profile = charlie_profile
        mesh.alice.store.save_contact(alice_charlie)

        alice_local = mesh.alice.store.load_local_profile()
        assert alice_local is not None
        alice_profile = create_delivery_profile(
            mesh.alice.identity,
            relay_descriptors=list(charlie_profile.relay_descriptors)
            + [descriptor for descriptor in alice_local.relay_descriptors if descriptor.name != "charlie"],
            version=alice_local.version + 1,
        )
        mesh.alice.store.save_local_profile(alice_profile)
        bob_alice.delivery_profile = alice_profile
        mesh.bob.store.save_contact(bob_alice)

        updated_pin = resolve_tls_pin_for_url(
            f"{mesh.charlie_relay.relay_url}/healthz",
            store=mesh.bob.store,
            contact=bob_alice,
        )
        assert updated_pin == new_pin

        response = yakr_get(
            f"{mesh.charlie_relay.relay_url}/healthz",
            store=mesh.bob.store,
            contact=bob_alice,
            timeout=2.0,
        )
        assert response.status_code == 200

        with pytest.raises(Exception):
            yakr_get(
                f"{mesh.charlie_relay.relay_url}/healthz",
                explicit_pin=old_pin,
                timeout=2.0,
            )
    finally:
        mesh.stop()
