"""Independent hybrid KEX verifier for cross-implementation test vectors."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HYBRID_MASTER_INFO = b"yakr/v0.6/hybrid-master"


def verify_hybrid_master(
    *,
    identity_shared: bytes,
    ephemeral_shared: bytes,
    pq_secret: bytes,
    transcript_hash: bytes,
    expected_master: bytes,
) -> bool:
    x_secret = identity_shared + ephemeral_shared
    derived = HKDF(hashes.SHA256(), 32, transcript_hash, HYBRID_MASTER_INFO).derive(x_secret + pq_secret)
    return derived == expected_master
