from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as nacl_bindings

MASTER_INFO = b"yakr/v0.1/master"
MESSAGE_KEY_INFO = b"yakr/v0.1/message-key"
MAILBOX_TAG_INFO = b"yakr/v0.1/mailbox-tag"
def hkdf_derive(
    ikm: bytes,
    info: bytes,
    *,
    length: int = 32,
    salt: bytes = b"",
) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)


def x25519_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_bytes: bytes,
) -> bytes:
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return private_key.exchange(peer)


def derive_master_secret(shared_secret: bytes, *, salt: bytes = b"") -> bytes:
    return hkdf_derive(shared_secret, MASTER_INFO, salt=salt)


def derive_message_key(master_secret: bytes, seq: int) -> bytes:
    info = MESSAGE_KEY_INFO + seq.to_bytes(8, "big")
    return hkdf_derive(master_secret, info)


def derive_mailbox_secret(master_secret: bytes, direction: str) -> bytes:
    info = MAILBOX_TAG_INFO + direction.encode("utf-8")
    return hkdf_derive(master_secret, info)


def xchacha_encrypt(key: bytes, plaintext: bytes, *, associated_data: bytes = b"") -> bytes:
    nonce = os.urandom(24)
    ciphertext = nacl_bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        associated_data,
        nonce,
        key,
    )
    return nonce + ciphertext


def xchacha_decrypt(
    key: bytes,
    payload: bytes,
    *,
    associated_data: bytes = b"",
) -> bytes:
    if len(payload) < 24:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = payload[:24], payload[24:]
    return nacl_bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        associated_data,
        nonce,
        key,
    )
