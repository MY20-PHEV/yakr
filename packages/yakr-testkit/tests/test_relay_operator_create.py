from __future__ import annotations

from pathlib import Path

import pytest

from yakr_core.delivery_profile import mailbox_descriptors
from yakr_core.identity import Identity
from yakr_core.relay_authorization import authorized_publish_relays
from yakr_core.relay_operator import (
    create_relay_operator,
    load_relay_operator_manifest,
    relay_operator_home,
)
from yakr_core.store import FileLocalStore


def test_create_relay_operator_pairs_with_owner(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    bundle = create_relay_operator(
        alice_store,
        operator_name="alice-ops",
        public_url="https://relay.example:8090",
        host_port=8090,
    )

    assert bundle.operator_home.exists()
    assert (bundle.operator_home / "identity.json").exists()
    assert (bundle.operator_home / "relay-tls" / "endpoint.cert.pem").exists()
    assert (bundle.operator_home / "relay-issuance" / "issuance.key").exists()
    assert (bundle.operator_home / "relay-issuance" / "issuance.pub").exists()
    assert (bundle.operator_home / "deploy" / "docker-compose.yml").exists()
    compose = (bundle.operator_home / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert "--require-capabilities" in compose
    assert "--relay-issuance-private-key" in compose

    manifest = load_relay_operator_manifest(bundle.operator_home)
    assert manifest.operator_name == "alice-ops"
    assert manifest.owner_name == "alice"
    assert manifest.public_url == "https://relay.example:8090"
    assert manifest.capability_issuance_public_b64
    assert len(manifest.capability_issuance_public_sha256) == 64

    owner_contact = alice_store.get_contact("alice-ops")
    assert owner_contact is not None
    assert owner_contact.delivery_profile is not None
    relay_urls = [d.url for d in mailbox_descriptors(owner_contact.delivery_profile)]
    assert relay_urls == ["https://relay.example:8090"]

    operator_owner = bundle.operator_store.get_contact("alice")
    assert operator_owner is not None
    assert operator_owner.peer_acked_my_profile_version >= 0


def test_create_relay_operator_authorized_for_profile_publish(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    create_relay_operator(
        alice_store,
        operator_name="alice-ops",
        public_url="https://relay.example:8090",
    )

    contacts = [c for name in alice_store.list_contacts() if (c := alice_store.get_contact(name))]
    authorized = authorized_publish_relays(
        identity_name=alice.name,
        contacts=contacts,
    )
    assert len(authorized) == 1
    assert authorized[0].name == "alice-ops"
    assert authorized[0].url == "https://relay.example:8090"


def test_create_relay_operator_rejects_owner_name(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    with pytest.raises(ValueError, match="must differ"):
        create_relay_operator(
            alice_store,
            operator_name="alice",
            public_url="https://relay.example:8090",
        )


def test_create_relay_operator_force_recreates(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    alice_store = FileLocalStore(tmp_path / "alice")
    alice_store.save_identity(alice)

    create_relay_operator(
        alice_store,
        operator_name="alice-ops",
        public_url="https://old.example:8090",
    )
    first_home = relay_operator_home(alice_store.root, "alice-ops")

    bundle = create_relay_operator(
        alice_store,
        operator_name="alice-ops",
        public_url="https://new.example:8090",
        force=True,
    )
    assert bundle.manifest.public_url == "https://new.example:8090"
    assert load_relay_operator_manifest(first_home).public_url == "https://new.example:8090"
