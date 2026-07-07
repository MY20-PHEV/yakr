from __future__ import annotations

from pathlib import Path

import pytest

from yakr_testkit.interop_verifier import (
    verify_all_vectors,
    verify_delivery_profile_vector,
    verify_hybrid_kex_vector,
    verify_inner_message_vector,
    verify_invite_vector,
    verify_mailbox_tag_vector,
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
