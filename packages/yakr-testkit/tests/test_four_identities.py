from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


@pytest.fixture
def four_identities(tmp_path: Path, relay_server: str):
    names = ("alice", "bob", "charlie", "dennis")
    homes = {name: tmp_path / name for name in names}
    env_base = {**os.environ, "YAKR_RELAY_URL": relay_server}

    for name, home in homes.items():
        home.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["yakr", "init", "--name", name, "--force"],
            check=True,
            env={**env_base, "YAKR_HOME": str(home), "YAKR_NAME": name},
        )

    subprocess.run(
        ["yakr", "contact-add", "bob", str(homes["bob"] / "public.json")],
        check=True,
        env={**env_base, "YAKR_HOME": str(homes["alice"]), "YAKR_NAME": "alice"},
    )
    subprocess.run(
        ["yakr", "contact-add", "alice", str(homes["alice"] / "public.json")],
        check=True,
        env={**env_base, "YAKR_HOME": str(homes["bob"]), "YAKR_NAME": "bob"},
    )

    return homes, relay_server


def test_four_identities_offline_delivery(four_identities) -> None:
    homes, relay_server = four_identities
    env_base = {**os.environ, "YAKR_RELAY_URL": relay_server}

    subprocess.run(
        ["yakr", "send", "bob", "hello from alice"],
        check=True,
        env={**env_base, "YAKR_HOME": str(homes["alice"]), "YAKR_NAME": "alice"},
    )

    result = subprocess.run(
        ["yakr", "fetch", "alice"],
        check=True,
        capture_output=True,
        text=True,
        env={**env_base, "YAKR_HOME": str(homes["bob"]), "YAKR_NAME": "bob"},
    )
    assert "hello from alice" in result.stdout

    repeat = subprocess.run(
        ["yakr", "fetch", "alice"],
        check=True,
        capture_output=True,
        text=True,
        env={**env_base, "YAKR_HOME": str(homes["bob"]), "YAKR_NAME": "bob"},
    )
    assert "No new messages" in repeat.stdout
