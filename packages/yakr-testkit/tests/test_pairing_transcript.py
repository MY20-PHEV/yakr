"""Cross-language pairing transcript test vectors."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519

import pytest

from yakr_core.crypto import hkdf_derive, x25519_shared_secret
from yakr_core.hybrid_pq import HYBRID_PQ_CAPABILITY, derive_hybrid_master, kem_decapsulate
from yakr_core.invite import InviteBundle, invite_supports_hybrid
from yakr_core.pairing import PAIR_MASTER_INFO, PairingRequest, pairing_transcript

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "spec" / "test-vectors-v1" / "pairing_transcript.json"


def _load_vectors() -> list[dict]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def _invite_from_vector(vector: dict) -> InviteBundle:
    capabilities = ("direct_p2p",)
    kem_public = b""
    if vector.get("invite_kem_public_hex"):
        capabilities = ("direct_p2p", HYBRID_PQ_CAPABILITY)
        kem_public = bytes.fromhex(vector["invite_kem_public_hex"])
    return InviteBundle(
        protocol=vector.get("invite_protocol", "yakr-v0.4"),
        inviter_name="alice",
        signing_public=bytes.fromhex(vector["invite_signing_public_hex"]),
        agreement_public=bytes.fromhex(vector["invite_agreement_public_hex"]),
        invite_secret=bytes.fromhex(vector["invite_secret_hex"]),
        rendezvous_hint="https://rendezvous.test/v1",
        expires_at=1_700_000_000_000,
        capabilities=capabilities,
        signature=bytes(64),
        kem_public=kem_public,
    )


def _request_from_vector(vector: dict) -> PairingRequest:
    kem_ciphertext = b""
    if vector.get("kem_ciphertext_hex"):
        kem_ciphertext = bytes.fromhex(vector["kem_ciphertext_hex"])
    return PairingRequest(
        invite_secret=bytes.fromhex(vector["invite_secret_hex"]),
        joiner_name="bob",
        joiner_signing_public=bytes.fromhex(vector["joiner_signing_public_hex"]),
        joiner_agreement_public=bytes.fromhex(vector["joiner_agreement_public_hex"]),
        joiner_ephemeral_public=bytes.fromhex(vector["joiner_ephemeral_public_hex"]),
        joiner_ratchet_public=bytes.fromhex(vector["joiner_ratchet_public_hex"]),
        joiner_profile=b"",
        kem_ciphertext=kem_ciphertext,
    )


def test_pairing_transcript_vectors() -> None:
    for vector in _load_vectors():
        invite = _invite_from_vector(vector)
        request = _request_from_vector(vector)
        inviter_ephemeral_public = bytes.fromhex(vector["inviter_ephemeral_public_hex"])
        inviter_ratchet_public = bytes.fromhex(vector["inviter_ratchet_public_hex"])

        transcript = pairing_transcript(invite, request, inviter_ephemeral_public, inviter_ratchet_public)
        assert transcript.hex() == vector["expected_transcript_hash_hex"]

        inv_agree = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(vector["inviter_agreement_private_hex"])
        )
        inv_eph = x25519.X25519PrivateKey.from_private_bytes(
            bytes.fromhex(vector["inviter_ephemeral_private_hex"])
        )
        join_agree_pub = bytes.fromhex(vector["joiner_agreement_public_hex"])
        join_eph_pub = bytes.fromhex(vector["joiner_ephemeral_public_hex"])

        identity_shared = x25519_shared_secret(inv_agree, join_agree_pub)
        ephemeral_shared = x25519_shared_secret(inv_eph, join_eph_pub)
        assert identity_shared.hex() == vector["expected_identity_shared_hex"]
        assert ephemeral_shared.hex() == vector["expected_ephemeral_shared_hex"]

        if invite_supports_hybrid(invite):
            pq_secret = kem_decapsulate(
                bytes.fromhex(vector["inviter_kem_secret_hex"]),
                bytes.fromhex(vector["kem_ciphertext_hex"]),
            )
            assert pq_secret.hex() == vector["expected_pq_secret_hex"]
            master = derive_hybrid_master(
                identity_shared=identity_shared,
                ephemeral_shared=ephemeral_shared,
                pq_secret=pq_secret,
                transcript_hash=transcript,
            )
        else:
            master = hkdf_derive(
                identity_shared + ephemeral_shared,
                PAIR_MASTER_INFO,
                salt=transcript,
            )
        assert master.hex() == vector["expected_master_secret_hex"]


@pytest.mark.parametrize("vector_name", ["classical-pairing-v1", "hybrid-pairing-v1"])
def test_pairing_transcript_matches_inviter_and_joiner_paths(vector_name: str) -> None:
    from yakr_core.pairing import derive_pair_master, derive_pair_master_joiner

    vector = next(item for item in _load_vectors() if item["name"] == vector_name)
    invite = _invite_from_vector(vector)
    request = _request_from_vector(vector)
    inv_agree = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["inviter_agreement_private_hex"])
    )
    inv_eph = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["inviter_ephemeral_private_hex"])
    )
    join_agree = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["joiner_agreement_private_hex"])
    )
    join_eph = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["joiner_ephemeral_private_hex"])
    )
    transcript = bytes.fromhex(vector["expected_transcript_hash_hex"])
    pq_secret = None
    if invite_supports_hybrid(invite):
        pq_secret = kem_decapsulate(
            bytes.fromhex(vector["inviter_kem_secret_hex"]),
            bytes.fromhex(vector["kem_ciphertext_hex"]),
        )
    inviter_master = derive_pair_master(
        inviter_agreement_private=inv_agree,
        joiner_agreement_public=bytes.fromhex(vector["joiner_agreement_public_hex"]),
        inviter_ephemeral_private=inv_eph,
        joiner_ephemeral_public=bytes.fromhex(vector["joiner_ephemeral_public_hex"]),
        transcript_hash=transcript,
        pq_secret=pq_secret,
    )
    joiner_master = derive_pair_master_joiner(
        joiner_agreement_private=join_agree,
        inviter_agreement_public=bytes.fromhex(vector["invite_agreement_public_hex"]),
        joiner_ephemeral_private=join_eph,
        inviter_ephemeral_public=bytes.fromhex(vector["inviter_ephemeral_public_hex"]),
        transcript_hash=transcript,
        pq_secret=pq_secret,
    )
    assert inviter_master == joiner_master
    assert inviter_master.hex() == vector["expected_master_secret_hex"]
