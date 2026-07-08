from __future__ import annotations

import base64
import time

import httpx

from yakr_core.http_client import yakr_get, yakr_post
from yakr_core.identity import Identity
from yakr_core.invite import InviteBundle
from yakr_core.pairing import (
    PairingRequest,
    PairingResponse,
    inviter_complete_pairing,
)
from cryptography.hazmat.primitives.asymmetric import x25519


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _relay_pin(invite: InviteBundle | None) -> bytes | None:
    if invite is None or not invite.rendezvous_tls_spki_sha256:
        return None
    return invite.rendezvous_tls_spki_sha256


def register_relay_pairing(
    relay_url: str,
    invite_secret: bytes,
    *,
    rendezvous_tls_spki_sha256: bytes | None = None,
) -> str:
    response = yakr_post(
        f"{relay_url.rstrip('/')}/v1/pair/register",
        explicit_pin=rendezvous_tls_spki_sha256,
        json={"invite_secret": _b64encode(invite_secret)},
        timeout=10.0,
    )
    response.raise_for_status()
    return response.json()["invite_tag"]


def poll_relay_pair_request(
    relay_url: str,
    invite_tag: str,
    *,
    rendezvous_tls_spki_sha256: bytes | None = None,
    timeout_secs: float = 60.0,
    poll_interval_secs: float = 0.25,
) -> PairingRequest:
    deadline = time.time() + timeout_secs
    base = relay_url.rstrip("/")
    while time.time() < deadline:
        response = yakr_get(
            f"{base}/v1/pair/pending/{invite_tag}",
            explicit_pin=rendezvous_tls_spki_sha256,
            timeout=10.0,
        )
        if response.status_code == 200:
            payload = response.json()
            return PairingRequest.from_bytes(_b64decode(str(payload["request"])))
        if response.status_code != 404:
            response.raise_for_status()
        time.sleep(poll_interval_secs)
    raise TimeoutError("timed out waiting for pairing request on relay")


def post_relay_pair_request(
    relay_url: str,
    request: PairingRequest,
    *,
    rendezvous_tls_spki_sha256: bytes | None = None,
) -> str:
    response = yakr_post(
        f"{relay_url.rstrip('/')}/v1/pair",
        explicit_pin=rendezvous_tls_spki_sha256,
        json={"request": _b64encode(request.to_bytes())},
        timeout=10.0,
    )
    response.raise_for_status()
    return str(response.json()["invite_tag"])


def post_relay_pair_response(
    relay_url: str,
    invite_secret: bytes,
    pairing_response: PairingResponse,
    *,
    rendezvous_tls_spki_sha256: bytes | None = None,
) -> None:
    response = yakr_post(
        f"{relay_url.rstrip('/')}/v1/pair/response",
        explicit_pin=rendezvous_tls_spki_sha256,
        json={
            "invite_secret": _b64encode(invite_secret),
            "response": _b64encode(pairing_response.to_bytes()),
        },
        timeout=10.0,
    )
    response.raise_for_status()


def poll_relay_pair_response(
    relay_url: str,
    invite_tag: str,
    *,
    rendezvous_tls_spki_sha256: bytes | None = None,
    timeout_secs: float = 60.0,
    poll_interval_secs: float = 0.25,
) -> PairingResponse:
    deadline = time.time() + timeout_secs
    base = relay_url.rstrip("/")
    while time.time() < deadline:
        response = yakr_get(
            f"{base}/v1/pair/{invite_tag}",
            explicit_pin=rendezvous_tls_spki_sha256,
            timeout=10.0,
        )
        if response.status_code == 200:
            payload = response.json()
            return PairingResponse.from_bytes(_b64decode(str(payload["response"])))
        if response.status_code != 404:
            response.raise_for_status()
        time.sleep(poll_interval_secs)
    raise TimeoutError("timed out waiting for pairing response on relay")


def inviter_wait_on_relay(
    relay_url: str,
    identity: Identity,
    invite: InviteBundle,
    *,
    inviter_profile: bytes = b"",
    timeout_secs: float = 60.0,
) -> tuple[PairingResponse, object]:
    relay_pin = _relay_pin(invite)
    invite_tag = register_relay_pairing(
        relay_url,
        invite.invite_secret,
        rendezvous_tls_spki_sha256=relay_pin,
    )
    request = poll_relay_pair_request(
        relay_url,
        invite_tag,
        rendezvous_tls_spki_sha256=relay_pin,
        timeout_secs=timeout_secs,
    )
    if request.invite_secret != invite.invite_secret:
        raise ValueError("pairing request invite secret mismatch")
    response, contact = inviter_complete_pairing(
        identity,
        invite,
        request,
        x25519.X25519PrivateKey.generate(),
        inviter_profile=inviter_profile,
    )
    post_relay_pair_response(
        relay_url,
        invite.invite_secret,
        response,
        rendezvous_tls_spki_sha256=relay_pin,
    )
    return response, contact
