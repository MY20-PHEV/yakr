from __future__ import annotations

import threading
from dataclasses import dataclass, field

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.message import OuterBlob


class DirectBlobBody(BaseModel):
    mailbox_tag: str
    expires_at: int
    ciphertext: str


@dataclass
class DirectServerState:
    profile: DeliveryProfile | None = None
    blobs: dict[str, dict[str, str | int]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)


def create_direct_app(state: DirectServerState) -> FastAPI:
    app = FastAPI(title="Yakr Direct Delivery", version="0.5.0")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/profile")
    def get_profile() -> dict[str, str]:
        if state.profile is None:
            raise HTTPException(status_code=404, detail="profile not published")
        return {"profile": state.profile.to_b64()}

    @app.post("/v1/direct/blobs")
    def store_blob(body: DirectBlobBody) -> dict[str, str]:
        with state.lock:
            state.blobs[body.mailbox_tag] = body.model_dump()
        return {"status": "stored"}

    @app.get("/v1/direct/blobs/{mailbox_tag}")
    def fetch_blob(mailbox_tag: str) -> list[dict[str, str | int]]:
        with state.lock:
            item = state.blobs.get(mailbox_tag)
        if item is None:
            return []
        return [item]

    return app
