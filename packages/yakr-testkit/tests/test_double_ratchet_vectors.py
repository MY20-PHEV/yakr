"""Frozen double-ratchet test vectors (P2-1)."""

from __future__ import annotations

import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.crypto import hkdf_derive
from yakr_core.ratchet import RATCHET_MAGIC, RECV_CHAIN_INFO, ROOT_INFO, SEND_CHAIN_INFO, RatchetState

FIXTURES = Path(__file__).resolve().parents[3] / "docs" / "spec" / "test-vectors-v1" / "double_ratchet.json"


def _load_vectors() -> list[dict]:
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


def _apply_fixed_dh(state: RatchetState, private_hex: str) -> None:
    private = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    state.dh_self_private = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    state.dh_self_public = public


def test_double_ratchet_bootstrap_vector() -> None:
    vector = next(item for item in _load_vectors() if item["name"] == "double-ratchet-bootstrap-v1")
    master = bytes.fromhex(vector["master_secret_hex"])

    root = hkdf_derive(master, ROOT_INFO)
    assert root.hex() == vector["alice_root_key_hex"]
    assert hkdf_derive(root, SEND_CHAIN_INFO).hex() == vector["alice_send_chain_hex"]
    assert hkdf_derive(root, RECV_CHAIN_INFO).hex() == vector["alice_recv_chain_hex"]

    alice = RatchetState.from_master(master, is_initiator=True)
    bob = RatchetState.from_master(master, is_initiator=False)
    _apply_fixed_dh(alice, vector["alice_dh_self_private_hex"])
    _apply_fixed_dh(bob, vector["bob_dh_self_private_hex"])

    assert alice.dh_self_public.hex() == vector["alice_dh_self_public_hex"]
    assert bob.dh_self_public.hex() == vector["bob_dh_self_public_hex"]

    ciphertext = alice.encrypt(bytes.fromhex(vector["plaintext_hex"]))
    header_end = len(RATCHET_MAGIC) + 32 + 8
    assert ciphertext[: len(RATCHET_MAGIC)] == RATCHET_MAGIC
    assert ciphertext[len(RATCHET_MAGIC) : len(RATCHET_MAGIC) + 32].hex() == vector["header_dh_public_hex"]
    prev_n, message_n = struct.unpack(">II", ciphertext[len(RATCHET_MAGIC) + 32 : header_end])
    assert prev_n == vector["header_prev_n"]
    assert message_n == vector["header_message_n"]
    assert len(ciphertext) > header_end
    assert bob.decrypt(ciphertext) == bytes.fromhex(vector["plaintext_hex"])
