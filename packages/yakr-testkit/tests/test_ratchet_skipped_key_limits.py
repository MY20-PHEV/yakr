"""Ratchet skipped-key DoS bounds (P2-5)."""

from __future__ import annotations

import secrets
import struct

import pytest

from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.ratchet import MAX_SKIP_GAP, RATCHET_MAGIC, RatchetState


def _paired_ratchets() -> tuple[RatchetState, RatchetState]:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    assert contact.ratchet is not None
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    assert bob_contact.ratchet is not None
    return contact.ratchet, bob_contact.ratchet


def test_ratchet_decrypts_first_message() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    ciphertext = alice_ratchet.encrypt(b"hello")
    assert bob_ratchet.decrypt(ciphertext) == b"hello"


def test_ratchet_rejects_excessive_skip_gap() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    first = alice_ratchet.encrypt(b"first")
    bob_ratchet.decrypt(first)

    peer_public = first[len(RATCHET_MAGIC) : len(RATCHET_MAGIC) + 32]
    future_n = bob_ratchet.recv_n + MAX_SKIP_GAP + 1
    forged = (
        RATCHET_MAGIC
        + peer_public
        + struct.pack(">II", 0, future_n)
        + secrets.token_bytes(32)
    )
    with pytest.raises(ValueError, match="skip gap too large"):
        bob_ratchet.decrypt(forged)


def test_ratchet_clears_skipped_keys_on_dh_step() -> None:
    _, bob_ratchet = _paired_ratchets()
    bob_ratchet.skipped_keys["dead:beef"] = "AA"
    bob_ratchet._dh_ratchet(secrets.token_bytes(32))
    assert bob_ratchet.skipped_keys == {}
