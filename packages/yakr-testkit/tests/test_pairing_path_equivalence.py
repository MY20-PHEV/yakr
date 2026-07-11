"""Pairing transcript invariance across transport paths (P2-2 / G4)."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.identity import Identity
from yakr_core.invite import create_invite, verify_invite
from yakr_core.pairing import (
    OFFLINE_RENDEZVOUS_HINT,
    build_offline_pairing_request,
    build_pairing_request,
    finish_offline_pairing,
    inviter_complete_pairing,
    pair_request_from_url,
    pair_request_to_url,
    pair_response_from_url,
    respond_to_pair_request,
)


def test_offline_url_round_trip_preserves_request_bytes() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    request, _, request_url = build_offline_pairing_request(bob, invite, joiner_name="bob")
    assert pair_request_from_url(request_url).to_bytes() == request.to_bytes()


def test_online_and_offline_paths_same_transcript_and_master() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    inviter_ephemeral = x25519.X25519PrivateKey.generate()

    online_invite = create_invite(alice, rendezvous_hint="https://rendezvous.test/v1")
    offline_invite = create_invite(alice, rendezvous_hint=OFFLINE_RENDEZVOUS_HINT)
    verify_invite(online_invite)
    verify_invite(offline_invite)
    assert online_invite.invite_secret != offline_invite.invite_secret

    for invite in (online_invite, offline_invite):
        request, secrets = build_pairing_request(bob, invite, joiner_name="bob")

        direct_response, direct_contact = inviter_complete_pairing(
            alice,
            invite,
            request,
            inviter_ephemeral,
        )
        offline_response, offline_contact, response_url = respond_to_pair_request(
            alice,
            invite,
            pair_request_from_url(pair_request_to_url(request)),
            inviter_ephemeral_private=inviter_ephemeral,
        )
        finished = finish_offline_pairing(
            bob,
            invite,
            request,
            secrets,
            response_url,
        )

        assert direct_response.transcript_hash == offline_response.transcript_hash
        assert pair_response_from_url(response_url).transcript_hash == direct_response.transcript_hash
        assert direct_contact.master_secret == offline_contact.master_secret == finished.master_secret
        assert direct_contact.transcript_hash == finished.transcript_hash
