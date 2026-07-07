from __future__ import annotations

import json
from pathlib import Path

import pytest

from yakr_core.hybrid_pq import (
    HYBRID_PQ_CAPABILITY,
    derive_hybrid_master,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate_keypair,
    needs_pq_rekey,
)
from yakr_core.identity import Identity
from yakr_core.invite import create_invite, invite_supports_hybrid, verify_invite
from yakr_core.pairing import (
    PairingResponse,
    build_pairing_request,
    inviter_complete_pairing,
    joiner_complete_pairing,
)
from yakr_core.session import Session
from yakr_core.errors import RekeyRequiredError
from cryptography.hazmat.primitives.asymmetric import x25519
from yakr_testkit.hybrid_verify import verify_hybrid_master

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "spec" / "test-vectors-v1" / "hybrid_kex.json"


def test_hybrid_kex_vectors_match_independent_verifier() -> None:
    vectors = json.loads(FIXTURES.read_text(encoding="utf-8"))
    for vector in vectors:
        identity_shared = bytes.fromhex(vector["identity_shared_hex"])
        ephemeral_shared = bytes.fromhex(vector["ephemeral_shared_hex"])
        pq_secret = bytes.fromhex(vector["pq_secret_hex"])
        transcript_hash = bytes.fromhex(vector["transcript_hash_hex"])
        expected = bytes.fromhex(vector["expected_master_hex"])

        master = derive_hybrid_master(
            identity_shared=identity_shared,
            ephemeral_shared=ephemeral_shared,
            pq_secret=pq_secret,
            transcript_hash=transcript_hash,
        )
        assert master == expected
        assert verify_hybrid_master(
            identity_shared=identity_shared,
            ephemeral_shared=ephemeral_shared,
            pq_secret=pq_secret,
            transcript_hash=transcript_hash,
            expected_master=expected,
        )


def test_hybrid_pairing_establishes_pq_session() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test", hybrid_pq=True)
    verify_invite(invite)
    assert invite_supports_hybrid(invite)
    assert HYBRID_PQ_CAPABILITY in invite.capabilities

    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    assert request.kem_ciphertext
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)

    assert alice_contact.hybrid_pq is True
    assert bob_contact.hybrid_pq is True
    assert alice_contact.master_secret == bob_contact.master_secret
    assert alice_contact.ratchet is not None
    assert alice_contact.ratchet.hybrid is True

    encrypted = Session(alice, alice_contact).encrypt_text("hybrid hello")
    inner = Session(bob, bob_contact).decrypt_outer(encrypted.outer_blob)
    assert inner.body == "hybrid hello"


def test_classical_invite_falls_back_without_pq() -> None:
    alice = Identity.generate("alice", hybrid_pq=False)
    bob = Identity.generate("bob", hybrid_pq=False)
    invite = create_invite(alice, rendezvous_hint="http://test", hybrid_pq=False)
    assert not invite_supports_hybrid(invite)

    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    assert not request.kem_ciphertext
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)
    assert alice_contact.hybrid_pq is False
    assert bob_contact.hybrid_pq is False
    assert alice_contact.master_secret == bob_contact.master_secret


def test_ml_kem_roundtrip() -> None:
    public_key, secret_key = kem_generate_keypair()
    ciphertext, enc_secret = kem_encapsulate(public_key)
    dec_secret = kem_decapsulate(secret_key, ciphertext)
    assert enc_secret == dec_secret


def test_pq_rekey_thresholds() -> None:
    assert not needs_pq_rekey(hybrid=False, session_started_at_ms=0, messages_sent=0)
    assert needs_pq_rekey(
        hybrid=True,
        session_started_at_ms=0,
        messages_sent=10_000,
        now_ms=1,
    )
    assert needs_pq_rekey(
        hybrid=True,
        session_started_at_ms=0,
        messages_sent=0,
        now_ms=7 * 24 * 60 * 60 * 1000,
    )


def test_session_blocks_send_when_rekey_required() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test", hybrid_pq=True)
    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    alice_contact.session_started_at = 0
    alice_contact.next_send_seq = 10_000
    session = Session(alice, alice_contact)
    with pytest.raises(RekeyRequiredError):
        session.encrypt_text("too old")
