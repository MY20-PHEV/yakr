"""Hybrid homelab Alice↔Bob random burst stress tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from yakr_testkit.hybrid_homelab_mesh import (
    assert_hybrid_trust_model,
    build_hybrid_homelab_mesh,
    hybrid_live_configured,
)
from yakr_testkit.hybrid_stress import assert_hybrid_stress_passed, run_hybrid_alice_bob_stress


@pytest.fixture
def hybrid_mesh(tmp_path: Path):
    previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
    previous_name = os.environ.pop("YAKR_RELAY_NAME", None)
    mesh = build_hybrid_homelab_mesh(tmp_path, live=False)
    try:
        yield mesh
    finally:
        mesh.stop()
        if previous_relay is None:
            os.environ.pop("YAKR_RELAY_URL", None)
        else:
            os.environ["YAKR_RELAY_URL"] = previous_relay
        if previous_name is None:
            os.environ.pop("YAKR_RELAY_NAME", None)
        else:
            os.environ["YAKR_RELAY_NAME"] = previous_name


def test_hybrid_trust_model(hybrid_mesh) -> None:
    assert_hybrid_trust_model(hybrid_mesh)


def test_hybrid_alice_bob_random_stress_simulated(hybrid_mesh) -> None:
    """Local Charlie entry + local Dennis mailbox (no VPS required)."""
    result = run_hybrid_alice_bob_stress(
        hybrid_mesh,
        total_messages=100,
        fetch_interval_secs=(0.05, 0.15),
        seed=42,
    )
    assert_hybrid_stress_passed(result)


@pytest.mark.homelab
def test_hybrid_alice_bob_random_stress_live(tmp_path: Path) -> None:
    if not hybrid_live_configured():
        pytest.skip("set DENNIS_URL for live hybrid homelab stress")
    previous_relay = os.environ.pop("YAKR_RELAY_URL", None)
    mesh = build_hybrid_homelab_mesh(tmp_path, live=True)
    try:
        assert_hybrid_trust_model(mesh)
        result = run_hybrid_alice_bob_stress(
            mesh,
            total_messages=100,
            fetch_interval_secs=(1.0, 3.0),
            seed=7,
        )
        assert_hybrid_stress_passed(result)
    finally:
        mesh.stop()
        if previous_relay is None:
            os.environ.pop("YAKR_RELAY_URL", None)
        else:
            os.environ["YAKR_RELAY_URL"] = previous_relay
