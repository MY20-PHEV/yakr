from __future__ import annotations

import time

import pytest

from yakr_core.crypto import derive_mailbox_secret
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.message import InnerMessage
from yakr_core.privacy import (
    BALANCED_DECOY_COUNT,
    HIGH_DECOY_COUNT,
    fetch_tags_for_mode,
    pad_plaintext,
    relay_delay_secs,
)
from yakr_core.session import Session


def _contact(mode: str) -> Contact:
    alice = Identity.generate("alice", hybrid_pq=False)
    bob = Identity.generate("bob", hybrid_pq=False)
    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    contact.privacy_mode = mode  # type: ignore[assignment]
    return contact


def _ciphertext_len(body: str, mode: str) -> int:
    alice = Identity.generate("alice", hybrid_pq=False)
    contact = _contact(mode)
    session = Session(alice, contact)
    encrypted = session.encrypt_text(body)
    return len(encrypted.outer_blob.ciphertext)


def test_balanced_padding_hides_message_size() -> None:
    """300 B and ~2 KiB bodies produce equal ciphertext length in balanced mode."""
    small = "x" * 300
    large = "y" * 2000
    small_len = _ciphertext_len(small, "balanced")
    large_len = _ciphertext_len(large, "balanced")
    assert small_len == large_len
    assert small_len > 4000


def test_fast_mode_no_padding() -> None:
    small = _ciphertext_len("hi", "fast")
    large = _ciphertext_len("x" * 500, "fast")
    assert large > small


def test_decoy_tags_expand_fetch_set() -> None:
    alice = Identity.generate("alice", hybrid_pq=False)
    contact = _contact("balanced")
    session = Session(alice, contact)
    deriver = session.mailbox_deriver(outbound=False)
    secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)

    fast_tags = fetch_tags_for_mode(deriver, session.recv_direction, "fast", mailbox_secret=secret)
    balanced_tags = fetch_tags_for_mode(
        deriver, session.recv_direction, "balanced", mailbox_secret=secret
    )
    high_tags = fetch_tags_for_mode(deriver, session.recv_direction, "high", mailbox_secret=secret)

    assert len(balanced_tags) == len(fast_tags) * (1 + BALANCED_DECOY_COUNT)
    assert len(high_tags) == len(fast_tags) * (1 + HIGH_DECOY_COUNT)


def test_high_mode_reduces_upload_fetch_correlation() -> None:
    """More fetches than uploads when decoy tags are queried."""
    alice = Identity.generate("alice", hybrid_pq=False)
    contact = _contact("high")
    session = Session(alice, contact)
    deriver = session.mailbox_deriver(outbound=False)
    secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)
    uploads = 1
    fetches = len(
        fetch_tags_for_mode(deriver, session.recv_direction, "high", mailbox_secret=secret)
    )
    assert fetches / uploads >= 4


def test_fast_mode_latency_within_2x_baseline() -> None:
    def bench(mode: str, rounds: int = 50) -> float:
        alice = Identity.generate("alice", hybrid_pq=False)
        bob = Identity.generate("bob", hybrid_pq=False)
        contact = Contact.establish(alice, "bob", export_public_bundle(bob))
        contact.privacy_mode = mode  # type: ignore[assignment]
        session = Session(alice, contact)
        start = time.perf_counter()
        for index in range(rounds):
            session.encrypt_text(f"msg-{index}")
        return time.perf_counter() - start

    fast_elapsed = bench("fast")
    assert fast_elapsed < 2.0
    balanced_elapsed = bench("balanced")
    assert fast_elapsed <= balanced_elapsed * 2


def test_pad_roundtrip() -> None:
    raw = InnerMessage.text(
        conversation_id="pairwise_a_b",
        sender_device_id="dev",
        seq=1,
        body="secret",
    ).to_bytes()
    padded, padding = pad_plaintext(raw, "balanced")
    assert padding > 0
    assert len(padded) == 4096


def test_relay_delay_ranges() -> None:
    assert relay_delay_secs("fast") == 0.0
    balanced = relay_delay_secs("balanced", seed=b"test-seed")
    assert 0 <= balanced <= 15
    high = relay_delay_secs("high", seed=b"test-seed")
    assert 5 <= high <= 90
