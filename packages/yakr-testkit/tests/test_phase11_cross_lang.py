"""Phase 11 — Python↔Rust cross-language pairing and relay interop."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.identity import Identity
from yakr_core.invite import create_invite
from yakr_core.message import OuterBlob
from yakr_core.pairing import (
    build_pairing_request,
    inviter_complete_pairing,
    joiner_complete_pairing,
)
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_testkit.cross_lang import (
    read_invite,
    read_pairing_request,
    read_pairing_response,
    rust_fetch,
    rust_home,
    rust_init,
    rust_send,
    run_rust,
    write_invite,
    write_pairing_request,
    write_pairing_response,
)


def _python_home(root: Path, name: str) -> FileLocalStore:
    store = FileLocalStore(root / f"py-{name}")
    identity = Identity.generate(name, hybrid_pq=False)
    store.save_identity(identity)
    return store


def _python_fetch_text(
    store: FileLocalStore,
    contact_name: str,
    relay_server: str,
) -> str:
    identity = store.load_identity()
    assert identity is not None
    contact = store.get_contact(contact_name)
    assert contact is not None
    session = Session(identity, contact)
    tags = session.mailbox_deriver(outbound=False).candidate_epochs(session.recv_direction)
    for tag in tags:
        fetch = httpx.get(f"{relay_server}/v1/blobs/{tag.tag_b64}", timeout=5.0)
        assert fetch.status_code == 200
        for item in fetch.json():
            inner = session.decrypt_outer(OuterBlob.from_relay_json(item))
            if inner.body:
                store.save_contact(session.contact)
                return inner.body
    raise AssertionError("no decryptable message found")


def _python_send(
    store: FileLocalStore,
    contact_name: str,
    message: str,
    relay_server: str,
) -> None:
    identity = store.load_identity()
    assert identity is not None
    contact = store.get_contact(contact_name)
    assert contact is not None
    session = Session(identity, contact)
    encrypted = session.encrypt_text(message)
    response = httpx.post(
        f"{relay_server}/v1/blobs",
        json=encrypted.outer_blob.to_relay_json(),
        timeout=5.0,
    )
    assert response.status_code == 201
    store.save_contact(session.contact)


@pytest.mark.cross_lang
def test_py_inviter_rust_joiner_send_fetch(relay_server: str, tmp_path: Path) -> None:
    """Python inviter pairs Rust joiner; Rust sends; Python fetches."""
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    alice_store = _python_home(tmp_path, "alice")
    alice = alice_store.load_identity()
    assert alice is not None

    invite = create_invite(alice, rendezvous_hint=relay_server, hybrid_pq=False)
    invite_path = artifact_dir / "invite.b64"
    write_invite(invite_path, invite)

    rust_init(tmp_path, "bob")
    request_path = artifact_dir / "request.b64"
    secrets_path = artifact_dir / "secrets.json"
    run_rust(
        [
            "interop",
            "joiner-request",
            "--name",
            "bob",
            "--home",
            str(rust_home(tmp_path, "bob")),
            "--invite",
            str(invite_path),
            "--out-request",
            str(request_path),
            "--out-secrets",
            str(secrets_path),
        ]
    )

    request = read_pairing_request(request_path)
    response, alice_contact = inviter_complete_pairing(
        alice,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
    )
    alice_store.save_contact(alice_contact)

    response_path = artifact_dir / "response.b64"
    write_pairing_response(response_path, response)

    run_rust(
        [
            "interop",
            "joiner-complete",
            "--name",
            "bob",
            "--home",
            str(rust_home(tmp_path, "bob")),
            "--invite",
            str(invite_path),
            "--request",
            str(request_path),
            "--secrets",
            str(secrets_path),
            "--response",
            str(response_path),
        ]
    )

    rust_send(tmp_path, "bob", "alice", "hello from rust", relay_server)
    body = _python_fetch_text(alice_store, "bob", relay_server)
    assert body == "hello from rust"


@pytest.mark.cross_lang
def test_rust_inviter_py_joiner_send_fetch(relay_server: str, tmp_path: Path) -> None:
    """Rust inviter pairs Python joiner; Python sends; Rust fetches."""
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    rust_init(tmp_path, "alice")
    invite_path = artifact_dir / "invite.b64"
    run_rust(
        [
            "interop",
            "create-invite",
            "--name",
            "alice",
            "--home",
            str(rust_home(tmp_path, "alice")),
            "--rendezvous",
            relay_server,
            "--out",
            str(invite_path),
            "--classical",
        ]
    )

    bob_store = _python_home(tmp_path, "bob")
    bob = bob_store.load_identity()
    assert bob is not None
    invite = read_invite(invite_path)
    request, secrets = build_pairing_request(bob, invite, joiner_name="bob")

    request_path = artifact_dir / "request.b64"
    write_pairing_request(request_path, request)

    response_path = artifact_dir / "response.b64"
    run_rust(
        [
            "interop",
            "inviter-complete",
            "--name",
            "alice",
            "--home",
            str(rust_home(tmp_path, "alice")),
            "--invite",
            str(invite_path),
            "--request",
            str(request_path),
            "--out-response",
            str(response_path),
        ]
    )

    response = read_pairing_response(response_path)
    bob_contact = joiner_complete_pairing(bob, invite, request, secrets, response)
    bob_store.save_contact(bob_contact)

    _python_send(bob_store, "alice", "hello from python", relay_server)
    stdout = rust_fetch(tmp_path, "alice", "bob", relay_server)
    assert "hello from python" in stdout
    assert "fetched 1 message(s)" in stdout
