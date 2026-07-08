from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _default_tls_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Legacy unit tests may use plain HTTP relays unless they opt into TLS."""
    if "YAKR_REQUIRE_TLS" not in os.environ:
        monkeypatch.setenv("YAKR_REQUIRE_TLS", "0")
