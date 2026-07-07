from __future__ import annotations

from pqcrypto.kem.ml_kem_768 import (
    CIPHERTEXT_SIZE,
    PLAINTEXT_SIZE,
    PUBLIC_KEY_SIZE,
    SECRET_KEY_SIZE,
    decrypt,
    encrypt,
    generate_keypair,
)

from yakr_core.crypto import hkdf_derive

HYBRID_MASTER_INFO = b"yakr/v0.6/hybrid-master"
HYBRID_PQ_CAPABILITY = "hybrid_pq"
PQ_REKEY_MAX_MESSAGES = 10_000
PQ_REKEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000


def kem_generate_keypair() -> tuple[bytes, bytes]:
    public_key, secret_key = generate_keypair()
    return public_key, secret_key


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError("invalid ML-KEM-768 public key length")
    ciphertext, shared_secret = encrypt(public_key)
    return ciphertext, shared_secret


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError("invalid ML-KEM-768 secret key length")
    if len(ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError("invalid ML-KEM-768 ciphertext length")
    return decrypt(secret_key, ciphertext)


def derive_hybrid_master(
    *,
    identity_shared: bytes,
    ephemeral_shared: bytes,
    pq_secret: bytes,
    transcript_hash: bytes,
) -> bytes:
    if len(pq_secret) != PLAINTEXT_SIZE:
        raise ValueError("invalid PQ shared secret length")
    x_secret = identity_shared + ephemeral_shared
    return hkdf_derive(x_secret + pq_secret, HYBRID_MASTER_INFO, salt=transcript_hash)


def needs_pq_rekey(
    *,
    hybrid: bool,
    session_started_at_ms: int,
    messages_sent: int,
    now_ms: int | None = None,
) -> bool:
    if not hybrid:
        return False
    import time

    now = int(time.time() * 1000) if now_ms is None else now_ms
    age_exceeded = now - session_started_at_ms >= PQ_REKEY_MAX_AGE_MS
    count_exceeded = messages_sent >= PQ_REKEY_MAX_MESSAGES
    return age_exceeded or count_exceeded
