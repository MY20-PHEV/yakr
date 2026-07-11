from __future__ import annotations

import base64
import random
import time
from dataclasses import dataclass, field
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from yakr_core.capability_grant import (
    CapabilityGrant,
    grant_allows_permission,
    issue_capability_grant,
    verify_capability_grant,
    verify_capability_request,
)
from yakr_core.onion import decode_entry_packet, decode_mailbox_packet
from yakr_core.relay import RelayRole
from yakr_core.relay_ticket import RelayTicket, verify_relay_ticket
from yakr_relay.capability_store import CapabilityGrantStore
from yakr_relay.pairing_store import PairingStore
from yakr_relay.store import BlobStore, _b64decode, _b64encode


class BlobStoreRequest(BaseModel):
    mailbox_tag: str
    expires_at: int
    ciphertext: str
    ticket: str | None = None


class BlobResponse(BaseModel):
    mailbox_tag: str
    expires_at: int
    ciphertext: str
    stored_at: int


class RelayPacketRequest(BaseModel):
    packet: str
    ticket: str | None = None


class IngestRequest(BaseModel):
    inner: str
    ticket: str | None = None


class PairRegisterRequest(BaseModel):
    invite_secret: str


class PairRequestBody(BaseModel):
    request: str


class PairResponseBody(BaseModel):
    invite_secret: str
    response: str


class CapabilityRegisterRequest(BaseModel):
    grant: str


class CapabilityIssueRequest(BaseModel):
    auth_public: str
    capability_id: str
    capability_generation: int
    issuance_salt: str
    permissions: list[str]
    ticket: str | None = None
    supersedes_capability_id: str | None = None


class CapabilityRevokeRequest(BaseModel):
    capability_id: str
    ticket: str


class FetchRequest(BaseModel):
    mailbox_tags: list[str]
    ticket: str | None = None


@dataclass
class RelayRuntime:
    role: RelayRole
    wrap_secret: bytes | None
    name: str
    require_tickets: bool = False
    require_capabilities: bool = False
    forward_delay_max_secs: int = 0
    relay_issuance_public: bytes = field(default_factory=bytes)
    relay_issuance_private: bytes = field(default_factory=bytes)
    relay_tls_spki_sha256: bytes = field(default_factory=bytes)


def _check_bootstrap_ticket(ticket_b64: str | None, *, runtime: RelayRuntime) -> None:
    if ticket_b64 is None:
        raise HTTPException(status_code=401, detail="relay ticket required for capability issue")
    try:
        ticket = RelayTicket.from_b64(ticket_b64)
        for permission in ("store", "fetch"):
            try:
                verify_relay_ticket(ticket, relay_name=runtime.name, permission=permission)
                return
            except ValueError:
                continue
        raise ValueError("relay ticket missing store or fetch permission")
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"invalid relay ticket: {exc}") from exc


def _check_ticket(ticket_b64: str | None, *, runtime: RelayRuntime, permission: str) -> None:
    if not runtime.require_tickets:
        return
    if ticket_b64 is None:
        raise HTTPException(status_code=401, detail="relay ticket required")
    try:
        ticket = RelayTicket.from_b64(ticket_b64)
        verify_relay_ticket(ticket, relay_name=runtime.name, permission=permission)
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"invalid relay ticket: {exc}") from exc


def _check_capability(
    request: Request,
    *,
    runtime: RelayRuntime,
    capability_store: CapabilityGrantStore,
    permission: str,
    body: bytes,
) -> None:
    if not runtime.require_capabilities:
        return
    if not runtime.relay_issuance_public:
        raise HTTPException(status_code=500, detail="relay missing issuance public key")
    grant_b64 = request.headers.get("Yakr-Capability-Grant")
    timestamp_raw = request.headers.get("Yakr-Capability-Timestamp")
    nonce_b64 = request.headers.get("Yakr-Capability-Nonce")
    signature_b64 = request.headers.get("Yakr-Capability-Signature")
    if not all([grant_b64, timestamp_raw, nonce_b64, signature_b64]):
        raise HTTPException(status_code=401, detail="capability headers required")
    try:
        grant = CapabilityGrant.from_b64(str(grant_b64))
        verify_capability_grant(
            grant,
            relay_signing_public=runtime.relay_issuance_public,
            relay_name=runtime.name,
            relay_tls_spki_sha256=runtime.relay_tls_spki_sha256,
        )
        if not capability_store.is_registered(grant):
            raise ValueError("capability grant not registered")
        if not grant_allows_permission(grant, permission):
            raise ValueError(f"capability missing permission: {permission}")
        verify_capability_request(
            grant,
            auth_public=grant.auth_public,
            signature=_b64decode(str(signature_b64)),
            method=request.method,
            path=request.url.path,
            body=body,
            timestamp_ms=int(timestamp_raw),
            nonce=_b64decode(str(nonce_b64)),
        )
        capability_store.consume_nonce(str(nonce_b64))
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"invalid capability: {exc}") from exc


def _authorize_request(
    request: Request,
    *,
    runtime: RelayRuntime,
    capability_store: CapabilityGrantStore,
    permission: str,
    body: bytes,
    ticket_b64: str | None,
) -> None:
    if runtime.require_capabilities:
        _check_capability(
            request,
            runtime=runtime,
            capability_store=capability_store,
            permission=permission,
            body=body,
        )
        return
    _check_ticket(ticket_b64, runtime=runtime, permission=permission)


def create_app(
    store: BlobStore,
    runtime: RelayRuntime | None = None,
    *,
    pairing_store: PairingStore | None = None,
    capability_store: CapabilityGrantStore | None = None,
) -> FastAPI:
    runtime = runtime or RelayRuntime(role="mailbox", wrap_secret=None, name="relay")
    pairing_store = pairing_store or PairingStore(store.root)
    capability_store = capability_store or CapabilityGrantStore(store.root / "capabilities")
    app = FastAPI(title="Yakr Relay", version="0.3.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        payload = {"status": "ok", "role": runtime.role, "name": runtime.name}
        if runtime.relay_issuance_public:
            payload["capability_issuance_public"] = _b64encode(runtime.relay_issuance_public)
        return payload

    @app.post("/v1/capabilities/issue", status_code=201)
    def issue_capability(request: CapabilityIssueRequest) -> dict[str, str]:
        if not runtime.relay_issuance_private:
            raise HTTPException(status_code=500, detail="relay missing issuance private key")
        _check_bootstrap_ticket(request.ticket, runtime=runtime)
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519

            auth_public = _b64decode(request.auth_public)
            capability_id = _b64decode(request.capability_id)
            issuance_salt = _b64decode(request.issuance_salt)
            if len(capability_id) != 16:
                raise ValueError("capability_id must be 16 bytes")
            if len(issuance_salt) != 16:
                raise ValueError("issuance_salt must be 16 bytes")
            relay_private = ed25519.Ed25519PrivateKey.from_private_bytes(runtime.relay_issuance_private)
            grant = issue_capability_grant(
                relay_private,
                capability_id=capability_id,
                capability_generation=request.capability_generation,
                relay_name=runtime.name,
                relay_tls_spki_sha256=runtime.relay_tls_spki_sha256,
                permissions=tuple(request.permissions),
                auth_public=auth_public,
            )
            if request.supersedes_capability_id:
                capability_store.revoke_with_overlap(_b64decode(request.supersedes_capability_id))
            capability_store.register(
                grant,
                relay_signing_public=runtime.relay_issuance_public,
                relay_name=runtime.name,
                relay_tls_spki_sha256=runtime.relay_tls_spki_sha256,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "issued", "grant": grant.to_b64()}

    @app.post("/v1/capabilities/register", status_code=201)
    def register_capability(request: CapabilityRegisterRequest) -> dict[str, str]:
        if not runtime.relay_issuance_public:
            raise HTTPException(status_code=500, detail="relay missing issuance public key")
        try:
            grant = CapabilityGrant.from_b64(request.grant)
            capability_store.register(
                grant,
                relay_signing_public=runtime.relay_issuance_public,
                relay_name=runtime.name,
                relay_tls_spki_sha256=runtime.relay_tls_spki_sha256,
            )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "registered", "capability_id": _b64encode(grant.capability_id)}

    @app.post("/v1/capabilities/revoke", status_code=200)
    def revoke_capability(request: CapabilityRevokeRequest) -> dict[str, str]:
        _check_bootstrap_ticket(request.ticket, runtime=runtime)
        try:
            capability_id = _b64decode(request.capability_id)
            if len(capability_id) != 16:
                raise ValueError("capability_id must be 16 bytes")
            capability_store.revoke_immediately(capability_id)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "revoked", "capability_id": request.capability_id}

    @app.post("/v1/blobs", status_code=201)
    async def store_blob(request: Request, payload: BlobStoreRequest) -> dict[str, str]:
        if runtime.role == "entry":
            raise HTTPException(status_code=405, detail="entry relay does not store blobs directly")
        body = await request.body()
        _authorize_request(
            request,
            runtime=runtime,
            capability_store=capability_store,
            permission="store",
            body=body,
            ticket_b64=payload.ticket,
        )
        try:
            store.store(
                _b64decode(payload.mailbox_tag),
                payload.expires_at,
                _b64decode(payload.ciphertext),
            )
        except ValueError as exc:
            status = 429 if "blob limit exceeded" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"status": "stored"}

    @app.post("/v1/fetch", response_model=list[BlobResponse])
    async def fetch_blobs_post(request: Request, payload: FetchRequest) -> list[BlobResponse]:
        if runtime.role == "entry":
            raise HTTPException(status_code=405, detail="entry relay does not fetch blobs")
        body = await request.body()
        _authorize_request(
            request,
            runtime=runtime,
            capability_store=capability_store,
            permission="fetch",
            body=body,
            ticket_b64=payload.ticket,
        )
        if not payload.mailbox_tags:
            raise HTTPException(status_code=400, detail="mailbox_tags required")
        items: list[BlobResponse] = []
        seen: set[tuple[str, int]] = set()
        for mailbox_tag in payload.mailbox_tags:
            try:
                tag_bytes = _b64decode(mailbox_tag)
            except Exception as exc:
                raise HTTPException(status_code=400, detail="invalid mailbox_tag") from exc
            for blob in store.fetch(tag_bytes):
                key = (_b64encode(blob.ciphertext), blob.stored_at)
                if key in seen:
                    continue
                seen.add(key)
                items.append(
                    BlobResponse(
                        mailbox_tag=_b64encode(blob.mailbox_tag),
                        expires_at=blob.expires_at,
                        ciphertext=_b64encode(blob.ciphertext),
                        stored_at=blob.stored_at,
                    )
                )
        return items

    @app.get("/v1/blobs/{mailbox_tag}", response_model=list[BlobResponse])
    def fetch_blobs_legacy(mailbox_tag: str) -> list[BlobResponse]:
        """Legacy v1 fetch — mailbox tag in URL path. Prefer POST /v1/fetch."""
        try:
            tag_bytes = _b64decode(mailbox_tag)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid mailbox_tag") from exc

        blobs = store.fetch(tag_bytes)
        return [
            BlobResponse(
                mailbox_tag=_b64encode(blob.mailbox_tag),
                expires_at=blob.expires_at,
                ciphertext=_b64encode(blob.ciphertext),
                stored_at=blob.stored_at,
            )
            for blob in blobs
        ]

    @app.post("/v1/relay", status_code=202)
    def relay_packet(request: RelayPacketRequest) -> dict[str, str]:
        if runtime.role not in ("entry", "both"):
            raise HTTPException(status_code=405, detail="not an entry relay")
        _check_ticket(request.ticket, runtime=runtime, permission="forward")
        if runtime.wrap_secret is None:
            raise HTTPException(status_code=500, detail="entry relay missing wrap secret")

        try:
            packet = base64.urlsafe_b64decode(request.packet + "=" * (-len(request.packet) % 4))
            next_url, inner_cipher = decode_entry_packet(packet, runtime.wrap_secret)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid relay packet") from exc

        if runtime.forward_delay_max_secs > 0:
            delay = random.uniform(0, runtime.forward_delay_max_secs)
            time.sleep(delay)

        response = httpx.post(
            next_url,
            json={"inner": _b64encode(inner_cipher), "ticket": request.ticket},
            timeout=10.0,
        )
        if response.status_code not in (201, 202):
            raise HTTPException(status_code=502, detail=f"forward failed: {response.text}")

        return {"status": "forwarded", "next_relay": next_url}

    @app.post("/v1/ingest", status_code=201)
    def ingest_packet(request: IngestRequest) -> dict[str, str]:
        if runtime.role not in ("mailbox", "both"):
            raise HTTPException(status_code=405, detail="not a mailbox relay")
        _check_ticket(request.ticket, runtime=runtime, permission="store")
        if runtime.wrap_secret is None:
            raise HTTPException(status_code=500, detail="mailbox relay missing wrap secret")

        try:
            outer = decode_mailbox_packet(_b64decode(request.inner), runtime.wrap_secret)
            store.store(outer.mailbox_tag, outer.expires_at, outer.ciphertext)
        except ValueError as exc:
            status = 429 if "blob limit exceeded" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid ingest packet") from exc

        return {"status": "stored"}

    @app.post("/v1/pair/register", status_code=201)
    def pair_register(request: PairRegisterRequest) -> dict[str, str]:
        try:
            secret = _b64decode(request.invite_secret)
            invite_tag = pairing_store.register(secret)
        except ValueError as exc:
            status = 409 if "consumed" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"invite_tag": invite_tag, "status": "registered"}

    @app.post("/v1/pair", status_code=202)
    def pair_store_request(request: PairRequestBody) -> dict[str, str]:
        try:
            pairing_request = _b64decode(request.request)
            from yakr_core.pairing import PairingRequest

            parsed = PairingRequest.from_bytes(pairing_request)
            invite_tag = pairing_store.store_request(parsed.invite_secret, pairing_request)
        except ValueError as exc:
            status = 409 if "consumed" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail="invalid pairing request") from exc
        return {"invite_tag": invite_tag, "status": "stored"}

    @app.get("/v1/pair/pending/{invite_tag}")
    def pair_pending(invite_tag: str) -> dict[str, str]:
        pending = pairing_store.get_pending_request(invite_tag)
        if pending is None:
            raise HTTPException(status_code=404, detail="no pending request")
        return {"request": _b64encode(pending)}

    @app.post("/v1/pair/response", status_code=201)
    def pair_store_response(request: PairResponseBody) -> dict[str, str]:
        try:
            secret = _b64decode(request.invite_secret)
            response = _b64decode(request.response)
            invite_tag = pairing_store.store_response(secret, response)
        except ValueError as exc:
            status = 409 if "consumed" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"invite_tag": invite_tag, "status": "complete"}

    @app.get("/v1/pair/{invite_tag}")
    def pair_fetch_response(invite_tag: str) -> dict[str, str]:
        response = pairing_store.get_response(invite_tag)
        if response is None:
            raise HTTPException(status_code=404, detail="response not ready")
        return {"response": _b64encode(response)}

    return app
