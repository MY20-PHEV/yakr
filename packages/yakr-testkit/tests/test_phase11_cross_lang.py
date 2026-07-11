"""Phase 11 — Python↔Rust cross-language pairing and relay interop."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.errors import DuplicateSeqError
from yakr_core.identity import Identity
from yakr_core.invite import create_invite, invite_supports_hybrid
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
    rust_create_invite,
    rust_fetch,
    rust_home,
    rust_init,
    rust_send,
    run_rust,
    write_invite,
    write_pairing_request,
    write_pairing_response,
)


def _python_home(root: Path, name: str, *, hybrid_pq: bool) -> FileLocalStore:
    store = FileLocalStore(root / f"py-{name}")
    identity = Identity.generate(name, hybrid_pq=hybrid_pq)
    store.save_identity(identity)
    return store


def _reload_python_home(root: Path, name: str) -> FileLocalStore:
    return FileLocalStore(root / f"py-{name}")


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
            try:
                inner = session.decrypt_outer(OuterBlob.from_relay_json(item))
            except DuplicateSeqError:
                continue
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


def _pair_py_inviter_rust_joiner(
    tmp_path: Path,
    relay_server: str,
    *,
    hybrid_pq: bool,
) -> tuple[FileLocalStore, Path]:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    alice_store = _python_home(tmp_path, "alice", hybrid_pq=hybrid_pq)
    alice = alice_store.load_identity()
    assert alice is not None

    invite = create_invite(alice, rendezvous_hint=relay_server, hybrid_pq=hybrid_pq)
    assert invite_supports_hybrid(invite) is hybrid_pq
    invite_path = artifact_dir / "invite.b64"
    write_invite(invite_path, invite)

    rust_init(tmp_path, "bob", classical=not hybrid_pq)
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
    assert alice_contact.hybrid_pq is hybrid_pq
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
    return alice_store, artifact_dir


def _pair_rust_inviter_py_joiner(
    tmp_path: Path,
    relay_server: str,
    *,
    hybrid_pq: bool,
) -> tuple[FileLocalStore, Path]:
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()

    rust_init(tmp_path, "alice", classical=not hybrid_pq)
    invite_path = artifact_dir / "invite.b64"
    rust_create_invite(
        tmp_path,
        "alice",
        relay_server,
        invite_path,
        classical=not hybrid_pq,
    )

    bob_store = _python_home(tmp_path, "bob", hybrid_pq=hybrid_pq)
    bob = bob_store.load_identity()
    assert bob is not None
    invite = read_invite(invite_path)
    assert invite_supports_hybrid(invite) is hybrid_pq
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
    assert bob_contact.hybrid_pq is hybrid_pq
    bob_store.save_contact(bob_contact)
    return bob_store, artifact_dir


@pytest.mark.cross_lang
def test_py_inviter_rust_joiner_send_fetch(relay_server: str, tmp_path: Path) -> None:
    """Python inviter pairs Rust joiner; Rust sends; Python fetches (classical)."""
    alice_store, _ = _pair_py_inviter_rust_joiner(tmp_path, relay_server, hybrid_pq=False)
    rust_send(tmp_path, "bob", "alice", "hello from rust", relay_server)
    body = _python_fetch_text(alice_store, "bob", relay_server)
    assert body == "hello from rust"


@pytest.mark.cross_lang
def test_rust_inviter_py_joiner_send_fetch(relay_server: str, tmp_path: Path) -> None:
    """Rust inviter pairs Python joiner; Python sends; Rust fetches (classical)."""
    bob_store, _ = _pair_rust_inviter_py_joiner(tmp_path, relay_server, hybrid_pq=False)
    _python_send(bob_store, "alice", "hello from python", relay_server)
    stdout = rust_fetch(tmp_path, "alice", "bob", relay_server)
    assert "hello from python" in stdout
    assert "fetched 1 message(s)" in stdout


@pytest.mark.cross_lang
def test_hybrid_py_inviter_rust_joiner_send_fetch_reply_restart(
    relay_server: str,
    tmp_path: Path,
) -> None:
    """Hybrid PQ: Python inviter, Rust joiner; send/fetch, reply, persisted restart."""
    alice_store, _ = _pair_py_inviter_rust_joiner(tmp_path, relay_server, hybrid_pq=True)

    rust_send(tmp_path, "bob", "alice", "hello from rust", relay_server)
    assert _python_fetch_text(alice_store, "bob", relay_server) == "hello from rust"

    _python_send(alice_store, "bob", "reply from python", relay_server)
    stdout = rust_fetch(tmp_path, "bob", "alice", relay_server)
    assert "reply from python" in stdout

    alice_reloaded = _reload_python_home(tmp_path, "alice")
    contact = alice_reloaded.get_contact("bob")
    assert contact is not None
    assert contact.hybrid_pq is True

    rust_send(tmp_path, "bob", "alice", "after restart", relay_server)
    assert _python_fetch_text(alice_reloaded, "bob", relay_server) == "after restart"


@pytest.mark.cross_lang
def test_hybrid_rust_inviter_py_joiner_send_fetch_reply_restart(
    relay_server: str,
    tmp_path: Path,
) -> None:
    """Hybrid PQ: Rust inviter, Python joiner; send/fetch, reply, persisted restart."""
    bob_store, _ = _pair_rust_inviter_py_joiner(tmp_path, relay_server, hybrid_pq=True)

    _python_send(bob_store, "alice", "hello from python", relay_server)
    stdout = rust_fetch(tmp_path, "alice", "bob", relay_server)
    assert "hello from python" in stdout

    rust_send(tmp_path, "alice", "bob", "reply from rust", relay_server)
    assert _python_fetch_text(bob_store, "alice", relay_server) == "reply from rust"

    bob_reloaded = _reload_python_home(tmp_path, "bob")
    contact = bob_reloaded.get_contact("alice")
    assert contact is not None
    assert contact.hybrid_pq is True

    _python_send(bob_reloaded, "alice", "after restart", relay_server)
    stdout = rust_fetch(tmp_path, "alice", "bob", relay_server)
    assert "after restart" in stdout
