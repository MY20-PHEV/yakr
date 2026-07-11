from __future__ import annotations

from pathlib import Path

import pytest

from yakr_testkit.interop_verifier import (
    verify_all_negative_vectors,
    verify_all_vectors,
    verify_delivery_profile_vector,
    verify_double_ratchet_vector,
    verify_hybrid_kex_vector,
    verify_inner_message_vector,
    verify_inner_receipt_vector,
    verify_invite_vector,
    verify_mailbox_tag_vector,
    verify_negative_vector,
    verify_outer_blob_vector,
    verify_pairing_transcript_vector,
)

VECTORS = Path(__file__).resolve().parents[3] / "docs" / "spec" / "test-vectors-v1"


def test_interop_verifier_all_vectors() -> None:
    verify_all_vectors(VECTORS)


def test_interop_hybrid_kex_independent() -> None:
    import json

    vectors = json.loads((VECTORS / "hybrid_kex.json").read_text(encoding="utf-8"))
    for vector in vectors:
        assert verify_hybrid_kex_vector(vector)


def test_interop_invite_independent() -> None:
    import json

    vector = json.loads((VECTORS / "invite.json").read_text(encoding="utf-8"))
    assert verify_invite_vector(vector)


def test_interop_profile_independent() -> None:
    import json

    vector = json.loads((VECTORS / "delivery_profile.json").read_text(encoding="utf-8"))
    assert verify_delivery_profile_vector(vector)


def test_interop_mailbox_tag_independent() -> None:
    import json

    vector = json.loads((VECTORS / "mailbox_tag.json").read_text(encoding="utf-8"))
    assert verify_mailbox_tag_vector(vector)


def test_interop_inner_message_independent() -> None:
    import json

    vector = json.loads((VECTORS / "inner_message.json").read_text(encoding="utf-8"))
    assert verify_inner_message_vector(vector)


def test_interop_inner_receipt_independent() -> None:
    import json

    vector = json.loads((VECTORS / "inner_receipt.json").read_text(encoding="utf-8"))
    assert verify_inner_receipt_vector(vector)


def test_interop_outer_blob_independent() -> None:
    import json

    vector = json.loads((VECTORS / "outer_blob.json").read_text(encoding="utf-8"))
    assert verify_outer_blob_vector(vector)


def test_interop_pairing_transcript_independent() -> None:
    import json

    vectors = json.loads((VECTORS / "pairing_transcript.json").read_text(encoding="utf-8"))
    for vector in vectors:
        assert verify_pairing_transcript_vector(vector)


def test_interop_double_ratchet_independent() -> None:
    import json

    vectors = json.loads((VECTORS / "double_ratchet.json").read_text(encoding="utf-8"))
    for vector in vectors:
        assert verify_double_ratchet_vector(vector)


def test_interop_negative_vectors_all() -> None:
    verify_all_negative_vectors(VECTORS)


def test_interop_negative_pairing_independent() -> None:
    import json

    vectors = json.loads((VECTORS / "negative" / "pairing.json").read_text(encoding="utf-8"))
    for vector in vectors:
        assert verify_negative_vector(vector, vectors_dir=VECTORS)


def test_interop_negative_ratchet_independent() -> None:
    import json

    vectors = json.loads((VECTORS / "negative" / "ratchet.json").read_text(encoding="utf-8"))
    for vector in vectors:
        assert verify_negative_vector(vector, vectors_dir=VECTORS)


def test_interop_negative_vectors_have_normative_outcomes() -> None:
    import json

    required = {
        "must_reject",
        "rejection_stage",
        "normative_error_code",
        "persistent_state_must_change",
        "retryable",
    }
    for path in sorted((VECTORS / "negative").glob("*.json")):
        items = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(items, list):
            items = [items]
        for vector in items:
            missing = required - set(vector)
            assert not missing, f"{path.name} ({vector.get('name')}): missing {missing}"
