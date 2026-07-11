"""Helpers for Phase 11 Python↔Rust cross-language interop tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from yakr_core.identity import b64decode, b64encode
from yakr_core.invite import InviteBundle
from yakr_core.pairing import PairingRequest, PairingResponse


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def rust_binary() -> Path:
    override = os.environ.get("YAKR_RUST_BIN")
    if override:
        return Path(override)
    release = repo_root() / "rust" / "target" / "release" / "yakr"
    if release.exists():
        return release
    return repo_root() / "rust" / "target" / "debug" / "yakr"


def ensure_rust_binary() -> Path:
    binary = rust_binary()
    if binary.exists():
        return binary
    subprocess.run(
        ["cargo", "build", "--release", "-p", "yakr-cli"],
        cwd=repo_root() / "rust",
        check=True,
    )
    return rust_binary()


def run_rust(args: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    binary = ensure_rust_binary()
    merged = os.environ.copy()
    if env:
        merged.update(env)
    result = subprocess.run(
        [str(binary), *args],
        capture_output=True,
        text=True,
        env=merged,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode,
            result.args,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result


def write_invite(path: Path, invite: InviteBundle) -> None:
    path.write_text(b64encode(invite.to_bytes()), encoding="utf-8")


def read_invite(path: Path) -> InviteBundle:
    return InviteBundle.from_bytes(b64decode(path.read_text(encoding="utf-8").strip()))


def write_pairing_request(path: Path, request: PairingRequest) -> None:
    path.write_text(b64encode(request.to_bytes()), encoding="utf-8")


def read_pairing_request(path: Path) -> PairingRequest:
    return PairingRequest.from_bytes(b64decode(path.read_text(encoding="utf-8").strip()))


def write_pairing_response(path: Path, response: PairingResponse) -> None:
    path.write_text(b64encode(response.to_bytes()), encoding="utf-8")


def read_pairing_response(path: Path) -> PairingResponse:
    return PairingResponse.from_bytes(b64decode(path.read_text(encoding="utf-8").strip()))


def rust_home(root: Path, name: str) -> Path:
    return root / name


def rust_init(root: Path, name: str) -> None:
    home = rust_home(root, name)
    run_rust(
        [
            "interop",
            "init",
            "--name",
            name,
            "--home",
            str(home),
            "--force",
            "--classical",
        ]
    )


def rust_send(root: Path, sender: str, contact: str, message: str, relay: str) -> None:
    home = rust_home(root, sender)
    run_rust(
        [
            "send",
            contact,
            message,
            "--relay",
            relay,
            "--home",
            str(home),
        ],
        env={"YAKR_NAME": sender},
    )


def rust_fetch(root: Path, receiver: str, contact: str, relay: str) -> str:
    home = rust_home(root, receiver)
    result = run_rust(
        [
            "fetch",
            contact,
            "--relay",
            relay,
            "--home",
            str(home),
        ],
        env={"YAKR_NAME": receiver},
    )
    return result.stdout
