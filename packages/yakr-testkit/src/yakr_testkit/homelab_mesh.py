"""Homelab mesh: Alice + Bob against remote Charlie and Dennis relays."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from yakr_core.delivery_profile import create_delivery_profile, relay_descriptor_for_operator
from yakr_core.http_client import yakr_get
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.invite import create_invite, invite_to_url
from yakr_core.store import FileLocalStore
from yakr_core.tls import endpoint_tls_spki_sha256
from yakr_testkit.mesh_client import MeshParticipant
from yakr_testkit.mesh_setup import CharlieMesh, _joiner_accept, _wait_relay_healthy
from yakr_cli.profile_cmds import build_local_profile
from yakr_cli.relay_pairing import inviter_wait_on_relay


def homelab_env_configured() -> bool:
    return bool(os.environ.get("CHARLIE_URL", "").strip() and os.environ.get("DENNIS_URL", "").strip())


def _wrap_secret(env_name: str, *, fallback_seed: bytes) -> bytes:
    raw = os.environ.get(env_name)
    if raw:
        padding = "=" * (-len(raw) % 4)
        return base64.urlsafe_b64decode(raw + padding)
    return hashlib.sha256(fallback_seed).digest()


def _load_operator_identity(home: Path, name: str) -> Identity:
    identity_path = home / "identity.json"
    if identity_path.exists():
        return Identity.load(identity_path)
    raise FileNotFoundError(
        f"operator identity not found at {identity_path}; "
        f"run yakr init --name {name} and deploy relay TLS from that home"
    )


def assert_vps_trust_model(mesh: CharlieMesh) -> None:
    """Bob learns relay TLS pins via Alice only; operators are not cross-paired."""
    assert mesh.bob.store.get_contact("alice") is not None
    assert mesh.bob.store.get_contact("charlie") is None
    assert mesh.bob.store.get_contact("dennis") is None
    assert mesh.charlie.store.get_contact("dennis") is None
    assert mesh.dennis.store.get_contact("charlie") is None


@dataclass
class RemoteRelayHandle:
    """Remote relay on a VPS; optional SSH stop/start for outage tests."""

    name: str
    relay_url: str
    wrap_secret: bytes
    tls_spki_sha256: bytes
    vps_host: str | None = None
    container_name: str = ""
    local: bool = False

    def stop(self) -> None:
        if not self.vps_host or not self.container_name:
            raise RuntimeError(f"no VPS control for relay {self.name}")
        subprocess.run(
            ["ssh", self.vps_host, f"docker stop {self.container_name}"],
            check=True,
            capture_output=True,
            text=True,
        )
        _wait_relay_down(self.relay_url, tls_spki=self.tls_spki_sha256)

    def start(self) -> None:
        if not self.vps_host or not self.container_name:
            raise RuntimeError(f"no VPS control for relay {self.name}")
        subprocess.run(
            ["ssh", self.vps_host, f"docker start {self.container_name}"],
            check=True,
            capture_output=True,
            text=True,
        )
        _wait_relay_healthy(self.relay_url, tls_spki=self.tls_spki_sha256)


def _wait_relay_down(relay_url: str, *, tls_spki: bytes | None = None, timeout_secs: float = 15.0) -> None:
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        try:
            response = yakr_get(f"{relay_url}/healthz", explicit_pin=tls_spki, timeout=1.0)
            if response.status_code != 200:
                return
        except (httpx.HTTPError, OSError, RuntimeError, ValueError):
            return
        time.sleep(0.25)
    raise RuntimeError(f"relay still healthy at {relay_url}")


def _remote_relay(
    name: str,
    url: str,
    wrap_secret: bytes,
    identity: Identity,
) -> RemoteRelayHandle:
    url = url.rstrip("/")
    vps_env = f"{name.upper()}_VPS_HOST"
    container_env = f"{name.upper()}_CONTAINER"
    return RemoteRelayHandle(
        name=name,
        relay_url=url,
        wrap_secret=wrap_secret,
        tls_spki_sha256=endpoint_tls_spki_sha256(identity),
        vps_host=os.environ.get(vps_env) or os.environ.get("VPS_HOST"),
        container_name=os.environ.get(container_env, f"yakr-{name}"),
    )


def build_homelab_mesh(tmp_path: Path) -> CharlieMesh:
    """Build Alice/Bob mesh against CHARLIE_URL + DENNIS_URL (VPS trust model).

    Requires homelab relays deployed with TLS certs from the operator homes:
      CHARLIE_OPERATOR_HOME  (default: tmp_path/charlie-operator)
      DENNIS_OPERATOR_HOME   (default: tmp_path/dennis-operator)

    Optional outage control:
      CHARLIE_VPS_HOST / DENNIS_VPS_HOST (or VPS_HOST)
      CHARLIE_CONTAINER / DENNIS_CONTAINER (default yakr-charlie / yakr-dennis)
    """
    os.environ["YAKR_REQUIRE_TLS"] = "1"
    charlie_url = os.environ["CHARLIE_URL"].rstrip("/")
    dennis_url = os.environ["DENNIS_URL"].rstrip("/")

    charlie_operator_home = Path(
        os.environ.get("CHARLIE_OPERATOR_HOME", str(tmp_path / "charlie-operator"))
    )
    dennis_operator_home = Path(
        os.environ.get("DENNIS_OPERATOR_HOME", str(tmp_path / "dennis-operator"))
    )

    charlie_wrap = _wrap_secret("CHARLIE_WRAP_SECRET", fallback_seed=b"yakr-demo-vps-charlie-wrap-v0")
    dennis_wrap = _wrap_secret("DENNIS_WRAP_SECRET", fallback_seed=b"yakr-demo-vps-dennis-wrap-v0")

    charlie = _load_operator_identity(charlie_operator_home, "charlie")
    dennis = _load_operator_identity(dennis_operator_home, "dennis")
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    charlie_relay = _remote_relay("charlie", charlie_url, charlie_wrap, charlie)
    dennis_relay = _remote_relay("dennis", dennis_url, dennis_wrap, dennis)

    _wait_relay_healthy(charlie_relay.relay_url, tls_spki=charlie_relay.tls_spki_sha256)
    _wait_relay_healthy(dennis_relay.relay_url, tls_spki=dennis_relay.tls_spki_sha256)

    alice_store = FileLocalStore(tmp_path / "alice")
    bob_store = FileLocalStore(tmp_path / "bob")
    charlie_store = FileLocalStore(tmp_path / "charlie")
    dennis_store = FileLocalStore(tmp_path / "dennis")
    alice_store.save_identity(alice)
    bob_store.save_identity(bob)
    charlie_store.save_identity(charlie)
    dennis_store.save_identity(dennis)

    charlie_descriptor = relay_descriptor_for_operator(
        charlie, "both", charlie_relay.relay_url, charlie_wrap
    )
    dennis_descriptor = relay_descriptor_for_operator(
        dennis, "both", dennis_relay.relay_url, dennis_wrap
    )
    charlie_profile = create_delivery_profile(charlie, relay_descriptors=[charlie_descriptor])
    charlie_store.save_local_profile(charlie_profile)

    dennis_profile = create_delivery_profile(dennis, relay_descriptors=[dennis_descriptor])
    dennis_store.save_local_profile(dennis_profile)

    alice_charlie = Contact.establish(alice, "charlie", export_public_bundle(charlie))
    alice_charlie.delivery_profile = charlie_profile
    alice_store.save_contact(alice_charlie)

    alice_dennis = Contact.establish(alice, "dennis", export_public_bundle(dennis))
    alice_dennis.delivery_profile = dennis_profile
    alice_store.save_contact(alice_dennis)

    charlie_alice = Contact.establish(charlie, "alice", export_public_bundle(alice))
    charlie_store.save_contact(charlie_alice)

    dennis_alice = Contact.establish(dennis, "alice", export_public_bundle(alice))
    dennis_store.save_contact(dennis_alice)

    alice_profile = create_delivery_profile(
        alice,
        relay_descriptors=[charlie_descriptor, dennis_descriptor],
    )
    alice_store.save_local_profile(alice_profile)

    invite = create_invite(
        alice,
        rendezvous_hint=charlie_relay.relay_url,
        rendezvous_tls_spki_sha256=charlie_profile.endpoint_tls_spki_sha256,
    )
    invite_url = invite_to_url(invite)
    joiner_error: list[Exception] = []

    def run_joiner() -> None:
        try:
            time.sleep(0.15)
            _joiner_accept(charlie_relay.relay_url, invite_url, bob_store, bob)
        except Exception as exc:
            joiner_error.append(exc)

    import threading

    joiner_thread = threading.Thread(target=run_joiner)
    joiner_thread.start()

    inviter_profile = build_local_profile(alice, store=alice_store)
    _, alice_bob = inviter_wait_on_relay(
        charlie_relay.relay_url,
        alice,
        invite,
        inviter_profile=inviter_profile.to_bytes(),
        timeout_secs=60.0,
    )
    alice_bob.name = "bob"
    alice_store.save_contact(alice_bob)
    bob_alice = bob_store.get_contact("alice")
    if bob_alice is not None:
        bob_alice.delivery_profile = alice_profile
        bob_store.save_contact(bob_alice)
    joiner_thread.join(timeout=30)
    if joiner_error:
        raise joiner_error[0]

    return CharlieMesh(
        charlie_relay=charlie_relay,  # type: ignore[arg-type]
        dennis_relay=dennis_relay,  # type: ignore[arg-type]
        alice=MeshParticipant("alice", alice, alice_store, charlie_relay.relay_url),
        bob=MeshParticipant("bob", bob, bob_store, charlie_relay.relay_url),
        charlie=MeshParticipant("charlie", charlie, charlie_store, charlie_relay.relay_url),
        dennis=MeshParticipant("dennis", dennis, dennis_store, dennis_relay.relay_url),
    )
