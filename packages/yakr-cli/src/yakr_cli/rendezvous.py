from __future__ import annotations

import base64
import threading
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import x25519
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from yakr_core.identity import Contact, Identity
from yakr_core.invite import InviteBundle, verify_invite
from yakr_core.pairing import PairingRequest, inviter_complete_pairing


class PairRequestBody(BaseModel):
    request: str


@dataclass
class RendezvousState:
    invite: InviteBundle
    identity: Identity
    consumed: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)
    pending_ephemeral_private: x25519.X25519PrivateKey | None = None
    paired_contact: Contact | None = None


def create_rendezvous_app(state: RendezvousState) -> FastAPI:
    app = FastAPI(title="Yakr Rendezvous", version="0.4.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/pair")
    def pair(body: PairRequestBody) -> dict[str, str]:
        with state.lock:
            if state.consumed:
                raise HTTPException(status_code=409, detail="invite already consumed")
            try:
                request = PairingRequest.from_bytes(
                    base64.urlsafe_b64decode(body.request + "=" * (-len(body.request) % 4))
                )
            except Exception as exc:
                raise HTTPException(status_code=400, detail="invalid pairing request") from exc

            if request.invite_secret != state.invite.invite_secret:
                raise HTTPException(status_code=403, detail="invalid invite secret")

            try:
                verify_invite(state.invite)
            except ValueError as exc:
                raise HTTPException(status_code=410, detail=str(exc)) from exc

            if state.pending_ephemeral_private is None:
                state.pending_ephemeral_private = x25519.X25519PrivateKey.generate()

            response, contact = inviter_complete_pairing(
                state.identity,
                state.invite,
                request,
                state.pending_ephemeral_private,
            )
            state.consumed = True
            state.paired_contact = contact
            encoded = base64.urlsafe_b64encode(response.to_bytes()).decode("ascii").rstrip("=")
            return {"response": encoded}

    return app
