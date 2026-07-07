from __future__ import annotations

import base64
import random
import time
from dataclasses import dataclass
from typing import Literal

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from yakr_core.onion import decode_entry_packet, decode_mailbox_packet
from yakr_core.relay import RelayRole
from yakr_core.relay_ticket import RelayTicket, verify_relay_ticket
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


@dataclass
class RelayRuntime:
    role: RelayRole
    wrap_secret: bytes | None
    name: str
    require_tickets: bool = False
    forward_delay_max_secs: int = 0


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


def create_app(
    store: BlobStore,
    runtime: RelayRuntime | None = None,
    *,
    pairing_store: PairingStore | None = None,
) -> FastAPI:
    runtime = runtime or RelayRuntime(role="mailbox", wrap_secret=None, name="relay")
    pairing_store = pairing_store or PairingStore(store.root)
    app = FastAPI(title="Yakr Relay", version="0.3.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "role": runtime.role, "name": runtime.name}

    @app.post("/v1/blobs", status_code=201)
    def store_blob(request: BlobStoreRequest) -> dict[str, str]:
        if runtime.role == "entry":
            raise HTTPException(status_code=405, detail="entry relay does not store blobs directly")
        _check_ticket(request.ticket, runtime=runtime, permission="store")
        try:
            store.store(
                _b64decode(request.mailbox_tag),
                request.expires_at,
                _b64decode(request.ciphertext),
            )
        except ValueError as exc:
            status = 429 if "blob limit exceeded" in str(exc) else 400
            raise HTTPException(status_code=status, detail=str(exc)) from exc
        return {"status": "stored"}

    @app.get("/v1/blobs/{mailbox_tag}", response_model=list[BlobResponse])
    def fetch_blobs(mailbox_tag: str) -> list[BlobResponse]:
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
