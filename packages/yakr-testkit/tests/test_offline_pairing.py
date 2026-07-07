from __future__ import annotations

from pathlib import Path

import pytest

from yakr_core.identity import Identity
from yakr_core.invite import create_invite, invite_from_url, invite_to_url, verify_invite
from yakr_core.pairing import (
    OFFLINE_RENDEZVOUS_HINT,
    build_offline_pairing_request,
    finish_offline_pairing,
    pair_request_from_url,
    pair_request_to_url,
    pair_response_from_url,
    pair_response_to_url,
    pending_session_from_request,
    respond_to_pair_request,
)
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_core.delivery_profile import create_delivery_profile, RelayDescriptor
import secrets


def _profile_bytes(identity: Identity) -> bytes:
    return create_delivery_profile(
        identity,
        relay_descriptors=[
            RelayDescriptor("relay", "both", "https://relay.test", secrets.token_bytes(32)),
        ],
        direct_hints=["https://direct.test"],
    ).to_bytes()


def test_offline_pairing_urls_round_trip() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    invite_url = invite_to_url(invite)

    request, secrets, request_url = build_offline_pairing_request(
        bob,
        invite,
        joiner_name="bob",
        joiner_profile=_profile_bytes(bob),
    )
    assert request_url.startswith("yakr://pair-request/")
    assert pair_request_from_url(request_url).joiner_name == "bob"

    response, alice_contact, response_url = respond_to_pair_request(
        alice,
        invite,
        pair_request_from_url(request_url),
        inviter_profile=_profile_bytes(alice),
    )
    assert response_url.startswith("yakr://pair-response/")
    assert pair_response_from_url(response_url).transcript_hash == response.transcript_hash

    bob_contact = finish_offline_pairing(
        bob,
        invite,
        request,
        secrets,
        response_url,
    )
    assert alice_contact.master_secret == bob_contact.master_secret
    assert alice_contact.delivery_profile is not None
    assert bob_contact.delivery_profile is not None


def test_offline_pairing_establishes_encrypted_session() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    request, secrets, request_url = build_offline_pairing_request(bob, invite, joiner_name="bob")
    _, alice_contact, response_url = respond_to_pair_request(alice, invite, request)
    bob_contact = finish_offline_pairing(bob, invite, request, secrets, response_url)

    encrypted = Session(alice, alice_contact).encrypt_text("offline hello")
    inner = Session(bob, bob_contact).decrypt_outer(encrypted.outer_blob)
    assert inner.body == "offline hello"


def test_pending_pairing_session_persists(tmp_path: Path) -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    invite_url = invite_to_url(invite)
    request, secrets, _ = build_offline_pairing_request(bob, invite, joiner_name="bob")
    session = pending_session_from_request(invite_url, request, secrets)

    store = FileLocalStore(tmp_path / "bob")
    store.save_pending_pairing(session)
    loaded = store.load_pending_pairing()
    assert loaded is not None
    assert loaded.invite_url == invite_url
    assert loaded.request_url == pair_request_to_url(request)

    _, _, response_url = respond_to_pair_request(alice, invite, request)
    contact = finish_offline_pairing(
        bob,
        invite_from_url(loaded.invite_url),
        pair_request_from_url(loaded.request_url),
        loaded.secrets(),
        response_url,
    )
    store.clear_pending_pairing()
    assert contact.master_secret


def test_offline_invite_rejects_online_rendezvous_accept() -> None:
    invite = create_invite(Identity.generate("alice"), rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    verify_invite(invite)
    assert invite.rendezvous_hint == OFFLINE_RENDEZVOUS_HINT
