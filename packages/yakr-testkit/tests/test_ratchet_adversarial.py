"""Adversarial double-ratchet and session tests (P2-1)."""

from __future__ import annotations

import secrets
import struct

import pytest

from yakr_core.errors import DecryptError, DuplicateSeqError
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import InnerMessage, OuterBlob
from yakr_core.privacy import pad_plaintext
from yakr_core.ratchet import RATCHET_MAGIC, RatchetState
from yakr_core.session import Session


def _paired_ratchets() -> tuple[RatchetState, RatchetState]:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    assert alice_contact.ratchet is not None
    assert bob_contact.ratchet is not None
    return alice_contact.ratchet, bob_contact.ratchet


def _paired_sessions() -> tuple[Session, Session]:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    return Session(alice, alice_contact), Session(bob, bob_contact)


def test_out_of_order_wire_messages_within_skip_bounds() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    first = alice_ratchet.encrypt(b"one")
    third = alice_ratchet.encrypt(b"three")
    second = alice_ratchet.encrypt(b"two")

    assert bob_ratchet.decrypt(third) == b"three"
    assert bob_ratchet.decrypt(first) == b"one"
    assert bob_ratchet.decrypt(second) == b"two"


def test_duplicate_ratchet_message_rejected() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    msg = alice_ratchet.encrypt(b"once")
    assert bob_ratchet.decrypt(msg) == b"once"
    with pytest.raises(ValueError, match="already received"):
        bob_ratchet.decrypt(msg)


def test_dh_ratchet_step_advances_state() -> None:
    _, bob_ratchet = _paired_ratchets()
    root_before = bob_ratchet.root_key
    new_peer = secrets.token_bytes(32)
    bob_ratchet._dh_ratchet(new_peer)
    assert bob_ratchet.root_key != root_before
    assert bob_ratchet.dh_peer_public == new_peer
    assert bob_ratchet.send_n == 0
    assert bob_ratchet.recv_n == 0


def test_repeated_peer_dh_public_skips_ratchet() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    first = alice_ratchet.encrypt(b"a")
    bob_ratchet.decrypt(first)
    root_after_first = bob_ratchet.root_key
    peer = bob_ratchet.dh_peer_public

    second = alice_ratchet.encrypt(b"b")
    bob_ratchet.decrypt(second)
    assert bob_ratchet.root_key == root_after_first
    assert bob_ratchet.dh_peer_public == peer


def test_tampered_ciphertext_fails_aead() -> None:
    alice_ratchet, bob_ratchet = _paired_ratchets()
    msg = bytearray(alice_ratchet.encrypt(b"secret"))
    msg[-1] ^= 0xFF
    with pytest.raises(Exception):
        bob_ratchet.decrypt(bytes(msg))


def test_malformed_ratchet_header_rejected() -> None:
    _, bob_ratchet = _paired_ratchets()
    with pytest.raises(ValueError, match="too short"):
        bob_ratchet.decrypt(b"YKDR2" + b"\x00" * 10)
    with pytest.raises(ValueError, match="invalid ratchet header"):
        bob_ratchet.decrypt(b"BAD!!" + b"\x00" * 40)


def test_session_rolls_back_ratchet_on_out_of_order_inner_seq() -> None:
    alice_session, bob_session = _paired_sessions()
    first = alice_session.encrypt_text("first")
    second = alice_session.encrypt_text("second")
    third = alice_session.encrypt_text("third")
    bob_session.decrypt_outer(first.outer_blob)

    ratchet_before = bob_session.contact.ratchet.to_dict()
    recv_seq_before = bob_session.contact.last_recv_seq

    with pytest.raises(DuplicateSeqError, match="out-of-order seq"):
        bob_session.decrypt_outer(third.outer_blob)

    assert bob_session.contact.ratchet.to_dict() == ratchet_before
    assert bob_session.contact.last_recv_seq == recv_seq_before

    bob_session.decrypt_outer(second.outer_blob)
    bob_session.decrypt_outer(third.outer_blob)
    assert bob_session.contact.last_recv_seq == recv_seq_before + 2


def test_session_rejects_wrong_conversation_with_rollback() -> None:
    alice_session, bob_session = _paired_sessions()
    alice_session.encrypt_text("hello")
    ratchet_before = bob_session.contact.ratchet.to_dict()

    inner = InnerMessage.text(
        conversation_id="pairwise_eve_bob",
        sender_device_id=alice_session.identity.device_id,
        seq=bob_session.contact.last_recv_seq + 1,
        body="forged",
    )
    padded, _ = pad_plaintext(inner.to_bytes(), bob_session.contact.privacy_mode)
    ciphertext = alice_session.contact.ratchet.encrypt(padded)
    outer = OuterBlob(version=1, mailbox_tag=b"\x00" * 32, expires_at=9_999_999_999_999, ciphertext=ciphertext)

    with pytest.raises(DecryptError, match="conversation mismatch"):
        bob_session.decrypt_outer(outer)
    assert bob_session.contact.ratchet.to_dict() == ratchet_before


def test_contact_establish_ping_pong_does_not_rotate_dh_epoch() -> None:
    """Contact.establish has no pairing ratchet keys; DH epoch stays fixed in ping-pong."""
    alice_ratchet, bob_ratchet = _paired_ratchets()
    alice_root, bob_root = alice_ratchet.root_key, bob_ratchet.root_key
    alice_dh, bob_dh = alice_ratchet.dh_self_public, bob_ratchet.dh_self_public

    for i in range(3):
        bob_ratchet.decrypt(alice_ratchet.encrypt(f"a{i}".encode()))
        alice_ratchet.decrypt(bob_ratchet.encrypt(f"b{i}".encode()))

    assert alice_ratchet.root_key == alice_root
    assert bob_ratchet.root_key == bob_root
    assert alice_ratchet.dh_self_public == alice_dh
    assert bob_ratchet.dh_self_public == bob_dh


def test_pairing_path_rotates_dh_epoch() -> None:
    from yakr_core.invite import create_invite
    from yakr_core.pairing import build_pairing_request, inviter_complete_pairing, joiner_complete_pairing
    from yakr_core.session import Session
    from cryptography.hazmat.primitives.asymmetric import x25519

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    invite = create_invite(alice, rendezvous_hint="http://test")
    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)
    assert alice_contact.ratchet is not None
    assert bob_contact.ratchet is not None
    assert request.joiner_ratchet_public == bob_contact.ratchet.dh_self_public
    assert response.inviter_ratchet_public == alice_contact.ratchet.dh_self_public
    assert alice_contact.ratchet.dh_peer_public is None
    assert bob_contact.ratchet.dh_peer_public == response.inviter_ratchet_public

    alice_root = alice_contact.ratchet.root_key
    bob_root = bob_contact.ratchet.root_key
    alice_session = Session(alice, alice_contact)
    bob_session = Session(bob, bob_contact)
    bob_session.decrypt_outer(alice_session.encrypt_text("one").outer_blob)
    alice_session.decrypt_outer(bob_session.encrypt_text("two").outer_blob)
    assert alice_contact.ratchet.root_key != alice_root
    assert bob_contact.ratchet.root_key != bob_root
