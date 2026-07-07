from __future__ import annotations

import threading
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from yakr_relay.store import BlobStore, _b64decode, _b64encode


class BlobStoreRequest(BaseModel):
    mailbox_tag: str
    expires_at: int
    ciphertext: str


class BlobResponse(BaseModel):
    mailbox_tag: str
    expires_at: int
    ciphertext: str
    stored_at: int


def create_app(store: BlobStore) -> FastAPI:
    app = FastAPI(title="Yakr Relay", version="0.1.0")
    stop_event = threading.Event()

    @app.on_event("startup")
    def _start_sweeper() -> None:
        def sweeper() -> None:
            while not stop_event.is_set():
                store.sweep_expired()
                stop_event.wait(60)

        thread = threading.Thread(target=sweeper, daemon=True)
        thread.start()
        app.state.sweeper_stop = stop_event

    @app.on_event("shutdown")
    def _stop_sweeper() -> None:
        stop_event.set()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/blobs", status_code=201)
    def store_blob(request: BlobStoreRequest) -> dict[str, str]:
        try:
            store.store(
                _b64decode(request.mailbox_tag),
                request.expires_at,
                _b64decode(request.ciphertext),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
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

    return app
