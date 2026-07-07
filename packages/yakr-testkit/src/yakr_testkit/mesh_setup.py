from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx
import uvicorn

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.invite import create_invite, invite_to_url
from yakr_core.store import FileLocalStore
from yakr_cli.profile_cmds import build_local_profile
from yakr_cli.relay_pairing import inviter_wait_on_relay
from yakr_testkit.mesh_client import MeshParticipant
from yakr_core.invite import invite_from_url
from yakr_core.pairing import build_pairing_request, joiner_complete_pairing
from yakr_cli.relay_pairing import poll_relay_pair_response, post_relay_pair_request
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore


@dataclass
class CharlieMesh:
    relay_url: str
    relay_port: int
    alice: MeshParticipant
    bob: MeshParticipant
    charlie: MeshParticipant
    server: uvicorn.Server | None
    thread: threading.Thread | None
    relay_data_path: Path
    pairing_path: Path
    wrap_secret: bytes
    relay_host: str = "127.0.0.1"

    def stop_relay(self) -> None:
        if self.server is None:
            return
        self.server.should_exit = True
        assert self.thread is not None
        self.thread.join(timeout=5)
        self.server = None
        self.thread = None
        time.sleep(0.15)

    def start_relay(self) -> None:
        if self.server is not None:
            return
        store = BlobStore(self.relay_data_path)
        pairing_store = PairingStore(self.pairing_path)
        app = create_app(
            store,
            RelayRuntime(role="both", wrap_secret=self.wrap_secret, name="charlie"),
            pairing_store=pairing_store,
        )
        config = uvicorn.Config(
            app,
            host=self.relay_host,
            port=self.relay_port,
            log_level="error",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        deadline = time.time() + 5
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        if not server.started:
            raise RuntimeError("relay failed to start")
        self.server = server
        self.thread = thread
        self.relay_url = f"http://{self.relay_host}:{self.relay_port}"
        _wait_relay_healthy(self.relay_url)

    def stop(self) -> None:
        self.stop_relay()


def _wait_relay_healthy(relay_url: str, *, timeout_secs: float = 5.0) -> None:
    deadline = time.time() + timeout_secs
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            response = httpx.get(f"{relay_url}/healthz", timeout=0.5)
            if response.status_code == 200:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(0.05)
    raise RuntimeError(f"relay not healthy at {relay_url}: {last_error}")


def _start_relay_server(
    relay_data_path: Path,
    pairing_path: Path,
    wrap_secret: bytes,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> tuple[uvicorn.Server, threading.Thread, int]:
    store = BlobStore(relay_data_path)
    pairing_store = PairingStore(pairing_path)
    app = create_app(
        store,
        RelayRuntime(role="both", wrap_secret=wrap_secret, name="charlie"),
        pairing_store=pairing_store,
    )
    config = uvicorn.Config(app, host=host, port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("relay failed to start")
    relay_port = server.servers[0].sockets[0].getsockname()[1]
    relay_url = f"http://{host}:{relay_port}"
    _wait_relay_healthy(relay_url)
    return server, thread, relay_port


def _joiner_accept(relay_url: str, invite_url: str, bob_store: FileLocalStore, bob: Identity) -> Contact:
    bundle = invite_from_url(invite_url)
    profile = build_local_profile(bob, store=bob_store)
    request, pairing_secrets = build_pairing_request(
        bob,
        bundle,
        joiner_name="bob",
        joiner_profile=profile.to_bytes(),
    )
    invite_tag = post_relay_pair_request(relay_url, request)
    pairing_response = poll_relay_pair_response(relay_url, invite_tag, timeout_secs=30.0)
    contact = joiner_complete_pairing(bob, bundle, request, pairing_secrets, pairing_response)
    contact.name = "alice"
    bob_store.save_contact(contact)
    return contact


def build_charlie_mesh(tmp_path: Path, *, wrap_secret: bytes | None = None) -> CharlieMesh:
    wrap_secret = wrap_secret or secrets.token_bytes(32)
    relay_data_path = tmp_path / "relay-data"
    pairing_path = tmp_path / "pairing"
    server, thread, relay_port = _start_relay_server(relay_data_path, pairing_path, wrap_secret)
    relay_url = f"http://127.0.0.1:{relay_port}"

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    charlie = Identity.generate("charlie")

    alice_store = FileLocalStore(tmp_path / "alice")
    bob_store = FileLocalStore(tmp_path / "bob")
    charlie_store = FileLocalStore(tmp_path / "charlie")
    for ident, st in ((alice, alice_store), (bob, bob_store), (charlie, charlie_store)):
        st.save_identity(ident)

    charlie_profile = create_delivery_profile(
        charlie,
        relay_descriptors=[RelayDescriptor("charlie", "both", relay_url, wrap_secret)],
    )
    charlie_store.save_local_profile(charlie_profile)

    alice_charlie = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    alice_charlie.delivery_profile = charlie_profile
    alice_store.save_contact(alice_charlie)

    charlie_alice = Contact.establish(charlie, "alice", export_public_bundle(alice))
    charlie_store.save_contact(charlie_alice)

    invite = create_invite(alice, rendezvous_hint=relay_url)
    invite_url = invite_to_url(invite)
    joiner_error: list[Exception] = []

    def run_joiner() -> None:
        try:
            time.sleep(0.15)
            _joiner_accept(relay_url, invite_url, bob_store, bob)
        except Exception as exc:
            joiner_error.append(exc)

    joiner_thread = threading.Thread(target=run_joiner)
    joiner_thread.start()

    inviter_profile = build_local_profile(alice, store=alice_store)
    _, alice_bob = inviter_wait_on_relay(
        relay_url,
        alice,
        invite,
        inviter_profile=inviter_profile.to_bytes(),
        timeout_secs=30.0,
    )
    alice_bob.name = "bob"
    alice_store.save_contact(alice_bob)
    joiner_thread.join(timeout=15)
    if joiner_error:
        raise joiner_error[0]

    bob_charlie = Contact.establish(bob, "charlie", export_public_bundle(charlie))
    bob_charlie.delivery_profile = charlie_profile
    bob_store.save_contact(bob_charlie)

    charlie_bob = Contact.establish(charlie, "bob", export_public_bundle(bob))
    charlie_store.save_contact(charlie_bob)

    for st in (alice_store, bob_store, charlie_store):
        previous = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = relay_url
        try:
            profile = build_local_profile(st.load_identity(), store=st)  # type: ignore[arg-type]
            st.save_local_profile(profile)
        finally:
            if previous is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous

    return CharlieMesh(
        relay_url=relay_url,
        relay_port=relay_port,
        alice=MeshParticipant("alice", alice, alice_store, relay_url),
        bob=MeshParticipant("bob", bob, bob_store, relay_url),
        charlie=MeshParticipant("charlie", charlie, charlie_store, relay_url),
        server=server,
        thread=thread,
        relay_data_path=relay_data_path,
        pairing_path=pairing_path,
        wrap_secret=wrap_secret,
    )


def build_send_schedule() -> list[tuple[str, str, int]]:
    """Burst send schedule totaling 104 messages across all pairs."""
    return [
        ("alice", "bob", 8),
        ("alice", "charlie", 4),
        ("charlie", "alice", 6),
        ("bob", "alice", 7),
        ("alice", "bob", 5),
        ("charlie", "bob", 4),
        ("bob", "charlie", 3),
        ("alice", "charlie", 5),
        ("bob", "alice", 9),
        ("charlie", "alice", 4),
        ("alice", "bob", 6),
        ("charlie", "bob", 5),
        ("bob", "alice", 8),
        ("alice", "charlie", 3),
        ("bob", "charlie", 4),
        ("charlie", "alice", 7),
        ("alice", "bob", 4),
        ("bob", "alice", 6),
        ("charlie", "bob", 3),
        ("bob", "charlie", 2),
        ("alice", "charlie", 4),
        ("charlie", "alice", 5),
    ]


def build_fetch_rounds() -> list[tuple[str, str, bool]]:
    """Who fetches from whom, and whether to send delivery receipts."""
    return [
        ("bob", "alice", False),
        ("alice", "bob", False),
        ("charlie", "alice", True),
        ("alice", "charlie", False),
        ("bob", "alice", True),
        ("alice", "bob", True),
        ("charlie", "bob", False),
        ("bob", "charlie", True),
        ("alice", "charlie", True),
        ("charlie", "alice", False),
        ("bob", "alice", False),
        ("charlie", "bob", True),
        ("alice", "bob", False),
        ("bob", "charlie", False),
        ("charlie", "alice", True),
    ]


def run_mesh_stress(mesh: CharlieMesh) -> dict[str, object]:
    participants = {
        "alice": mesh.alice,
        "bob": mesh.bob,
        "charlie": mesh.charlie,
    }
    expected: list[tuple[str, str, str]] = []
    msg_id = 0

    for sender, recipient, count in build_send_schedule():
        party = participants[sender]
        for _ in range(count):
            body = f"m{msg_id:04d}:{sender}->{recipient}"
            party.send(recipient, body)
            expected.append((sender, recipient, body))
            msg_id += 1

    assert msg_id >= 100, f"expected >=100 sends, got {msg_id}"

    duplicate_fetch_hits = 0
    for fetcher, peer, send_receipts in build_fetch_rounds():
        first = participants[fetcher].fetch(peer, send_receipts=send_receipts)
        second = participants[fetcher].fetch(peer, send_receipts=send_receipts)
        duplicate_fetch_hits += len(second)

    pending_before_drain = sum(p.pending_count() for p in participants.values())

    for party in participants.values():
        party.flush_receipts()
        for peer in party.store.list_contacts():
            party.fetch(peer, send_receipts=True)

    for name in ("alice", "bob", "charlie"):
        participants[name].drain_receipts()

    received_by: dict[tuple[str, str], list[str]] = {}
    for recipient_name, party in participants.items():
        for sender_name in party.store.list_contacts():
            bodies = [
                body
                for _seq, body in party.store.list_inbound_messages(sender_name, party.identity)
            ]
            received_by[(sender_name, recipient_name)] = bodies

    missing: list[str] = []
    for sender, recipient, body in expected:
        got = received_by.get((sender, recipient), [])
        if body not in got:
            missing.append(body)

    pending_after = sum(p.pending_count() for p in participants.values())

    return {
        "total_sent": msg_id,
        "expected": expected,
        "received_by": received_by,
        "missing": missing,
        "duplicate_fetch_hits": duplicate_fetch_hits,
        "pending_before_drain": pending_before_drain,
        "pending_after": pending_after,
    }
