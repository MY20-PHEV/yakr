#!/usr/bin/env python3
"""Phase 5 delivery profile demo: profile update + direct P2P."""

from __future__ import annotations

import secrets
import subprocess
import threading
import time
from pathlib import Path

import httpx
import uvicorn

from yakr_core.delivery_profile import RelayDescriptor, create_delivery_profile
from yakr_core.identity import Identity
from yakr_core.relay import RelayNode, save_relay_network
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.direct_server import DirectServerState, create_direct_app
from yakr_cli.network import deliver_encrypted, fetch_direct_blobs
from yakr_relay.app import RelayRuntime, create_app
from yakr_relay.store import BlobStore


def _start_relay(name: str, role: str, secret: bytes | None, data_dir: Path) -> tuple[str, object]:
    store = BlobStore(data_dir)
    app = create_app(store, RelayRuntime(role=role, wrap_secret=secret, name=name))
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    return f"http://127.0.0.1:{port}", server


def main() -> None:
    root = Path(__file__).resolve().parents[1] / ".tmp-profile-demo"
    if root.exists():
        import shutil

        shutil.rmtree(root)
    root.mkdir()

    mailbox_a_secret = secrets.token_bytes(32)
    mailbox_b_secret = secrets.token_bytes(32)
    entry_secret = secrets.token_bytes(32)

    mailbox_a_url, mailbox_a_server = _start_relay("mailbox_a", "mailbox", mailbox_a_secret, root / "relay_a")
    mailbox_b_url, mailbox_b_server = _start_relay("mailbox_b", "mailbox", mailbox_b_secret, root / "relay_b")
    entry_url, entry_server = _start_relay("dennis", "both", entry_secret, root / "relay_entry")

    direct_state = DirectServerState()
    direct_app = create_direct_app(direct_state)
    direct_config = uvicorn.Config(direct_app, host="127.0.0.1", port=18100, log_level="error")
    direct_server = uvicorn.Server(direct_config)
    direct_thread = threading.Thread(target=direct_server.run, daemon=True)
    direct_thread.start()
    while not direct_server.started:
        time.sleep(0.05)
    direct_hint = "http://127.0.0.1:18100"

    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_store = FileLocalStore(root / "alice")
    bob_store = FileLocalStore(root / "bob")
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)

    from yakr_core.identity import Contact, export_public_bundle

    contact = Contact.establish(alice, "bob", export_public_bundle(bob))
    profile_v1 = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("dennis", "entry", entry_url, entry_secret),
            RelayDescriptor("mailbox_a", "mailbox", mailbox_a_url, mailbox_a_secret),
        ],
        direct_hints=[direct_hint],
        version=1,
    )
    contact.delivery_profile = profile_v1
    alice_store.save_contact(contact)

    encrypted = Session(alice, contact).encrypt_text("mailbox a message")
    deliver_encrypted(encrypted, contact=contact, route="dennis,mailbox_a", store=alice_store)
    print("Delivered via profile mailbox_a")

    profile_v2 = create_delivery_profile(
        bob,
        relay_descriptors=[
            RelayDescriptor("dennis", "entry", entry_url, entry_secret),
            RelayDescriptor("mailbox_b", "mailbox", mailbox_b_url, mailbox_b_secret),
        ],
        direct_hints=[direct_hint],
        version=2,
    )
    contact.delivery_profile = profile_v2
    alice_store.save_contact(contact)

    direct_state.profile = profile_v2
    encrypted_direct = Session(alice, contact).encrypt_text("direct p2p message")
    mode = deliver_encrypted(encrypted_direct, contact=contact, store=alice_store)
    print(f"Delivered via {mode}")

    bob_contact = Contact.establish(bob, "alice", export_public_bundle(alice))
    bob_contact.delivery_profile = create_delivery_profile(
        alice,
        relay_descriptors=[RelayDescriptor("relay", "both", mailbox_b_url, mailbox_b_secret)],
    )
    bob_session = Session(bob, bob_contact)
    deriver = bob_session.mailbox_deriver(outbound=False)
    tag = deriver.derive("alice->bob")
    blobs = fetch_direct_blobs(tag.tag_b64, [direct_hint])
    assert blobs, "expected direct blob"
    from yakr_core.message import OuterBlob

    outer = OuterBlob.from_relay_json(blobs[0])
    inner = bob_session.decrypt_outer(outer)
    print(f"bob received via direct: {inner.body}")

    for server in (mailbox_a_server, mailbox_b_server, entry_server):
        server.should_exit = True
    direct_server.should_exit = True
    print("Delivery profile demo complete")


if __name__ == "__main__":
    main()
