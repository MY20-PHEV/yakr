"""Pairing transcript PQ downgrade prevention."""

from __future__ import annotations

import pytest

from yakr_core.hybrid_pq import HYBRID_PQ_CAPABILITY
from yakr_core.invite import InviteBundle
from yakr_core.pairing import PairingRequest, pairing_transcript, validate_pairing_request_for_invite


def _classical_invite() -> InviteBundle:
    return InviteBundle(
        protocol="yakr-v0.4",
        inviter_name="alice",
        signing_public=bytes(32),
        agreement_public=bytes(32),
        invite_secret=bytes(32),
        rendezvous_hint="https://rendezvous.test/v1",
        expires_at=1_700_000_000_000,
        capabilities=("direct_p2p",),
        signature=bytes(64),
    )


def _hybrid_invite() -> InviteBundle:
    return InviteBundle(
        protocol="yakr-v0.6",
        inviter_name="alice",
        signing_public=bytes(32),
        agreement_public=bytes(32),
        invite_secret=bytes(32),
        rendezvous_hint="https://rendezvous.test/v1",
        expires_at=1_700_000_000_000,
        capabilities=(HYBRID_PQ_CAPABILITY,),
        signature=bytes(64),
        kem_public=bytes(32),
    )


def test_classical_invite_rejects_unexpected_kem_ciphertext() -> None:
    invite = _classical_invite()
    request = PairingRequest(
        invite_secret=invite.invite_secret,
        joiner_name="bob",
        joiner_signing_public=bytes(32),
        joiner_agreement_public=bytes(32),
        joiner_ephemeral_public=bytes(32),
        joiner_ratchet_public=bytes(32),
        kem_ciphertext=bytes(16),
    )
    with pytest.raises(ValueError, match="unexpected kem ciphertext"):
        validate_pairing_request_for_invite(invite, request)
    with pytest.raises(ValueError, match="unexpected kem ciphertext"):
        pairing_transcript(invite, request, bytes(32), bytes(32))


def test_hybrid_invite_requires_kem_ciphertext() -> None:
    invite = _hybrid_invite()
    request = PairingRequest(
        invite_secret=invite.invite_secret,
        joiner_name="bob",
        joiner_signing_public=bytes(32),
        joiner_agreement_public=bytes(32),
        joiner_ephemeral_public=bytes(32),
        joiner_ratchet_public=bytes(32),
        kem_ciphertext=b"",
    )
    with pytest.raises(ValueError, match="hybrid invite requires kem"):
        validate_pairing_request_for_invite(invite, request)
    with pytest.raises(ValueError, match="hybrid invite requires kem"):
        pairing_transcript(invite, request, bytes(32), bytes(32))
