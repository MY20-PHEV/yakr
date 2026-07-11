"""Malicious CBOR input fuzzing for wire parsers (P2-6)."""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Callable

import cbor2
import pytest

from yakr_core.capability_grant import CapabilityGrant
from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.identity import b64decode
from yakr_core.invite import InviteBundle
from yakr_core.pairing import PairingRequest, PairingResponse
from yakr_core.relay_ticket import RelayTicket

VECTORS_DIR = Path(__file__).resolve().parents[3] / "docs" / "spec" / "test-vectors-v1"

ACCEPTABLE_ERRORS = (
    ValueError,
    TypeError,
    KeyError,
    cbor2.CBORError,
    UnicodeDecodeError,
)


def _load_vector_b64(name: str, field: str) -> bytes:
    payload = json.loads((VECTORS_DIR / name).read_text(encoding="utf-8"))
    return b64decode(str(payload[field]))


def _fuzz_random(parser: Callable[[bytes], object], *, seed: int, rounds: int = 400) -> None:
    rng = random.Random(seed)
    for _ in range(rounds):
        size = rng.randint(0, 192)
        data = rng.randbytes(size)
        try:
            parser(data)
        except ACCEPTABLE_ERRORS:
            continue
        except Exception as exc:
            raise AssertionError(f"unexpected {type(exc).__name__}: {exc}") from exc


def _fuzz_mutated_valid(parser: Callable[[bytes], object], sample: bytes, *, seed: int) -> None:
    rng = random.Random(seed)
    if not sample:
        return
    for _ in range(200):
        data = bytearray(sample)
        flip_count = rng.randint(1, max(1, min(8, len(data))))
        for _ in range(flip_count):
            index = rng.randrange(len(data))
            data[index] ^= 1 << rng.randint(0, 7)
        try:
            parser(bytearray(data))
        except ACCEPTABLE_ERRORS:
            continue
        except Exception as exc:
            raise AssertionError(f"unexpected {type(exc).__name__}: {exc}") from exc


@pytest.mark.parametrize(
    ("parser", "sample"),
    [
        (DeliveryProfile.from_bytes, _load_vector_b64("delivery_profile.json", "profile_b64")),
        (InviteBundle.from_bytes, _load_vector_b64("invite.json", "bundle_b64")),
        (PairingRequest.from_bytes, b""),
        (PairingResponse.from_bytes, b""),
        (RelayTicket.from_bytes, b""),
        (CapabilityGrant.from_bytes, b""),
    ],
)
def test_cbor_parser_survives_random_input(parser, sample: bytes) -> None:
    _fuzz_random(parser, seed=hash(parser.__name__) % 10_000)


@pytest.mark.parametrize(
    ("parser", "sample"),
    [
        (DeliveryProfile.from_bytes, _load_vector_b64("delivery_profile.json", "profile_b64")),
        (InviteBundle.from_bytes, _load_vector_b64("invite.json", "bundle_b64")),
    ],
)
def test_cbor_parser_survives_mutated_valid_vectors(parser, sample: bytes) -> None:
    _fuzz_mutated_valid(parser, sample, seed=hash(parser.__name__) % 10_000)
