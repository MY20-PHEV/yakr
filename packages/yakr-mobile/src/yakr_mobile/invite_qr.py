"""QR helpers for invites and offline pairing payloads."""

from __future__ import annotations

import io
from dataclasses import dataclass

import qrcode

from yakr_core.identity import Identity
from yakr_core.invite import InviteBundle, create_invite, invite_to_url, safety_code, verify_invite


@dataclass(frozen=True)
class QrPayload:
    url: str
    qr_png: bytes


@dataclass(frozen=True)
class InvitePresentation:
    bundle: InviteBundle
    url: str
    safety: str
    qr_png: bytes


def url_to_qr_png(url: str) -> bytes:
    image = qrcode.make(url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def build_qr_payload(url: str) -> QrPayload:
    return QrPayload(url=url, qr_png=url_to_qr_png(url))


def build_invite_presentation(
    identity: Identity,
    *,
    rendezvous_hint: str,
    hybrid_pq: bool = False,
) -> InvitePresentation:
    bundle = create_invite(identity, rendezvous_hint=rendezvous_hint, hybrid_pq=hybrid_pq)
    verify_invite(bundle)
    url = invite_to_url(bundle)
    return InvitePresentation(
        bundle=bundle,
        url=url,
        safety=safety_code(bundle),
        qr_png=url_to_qr_png(url),
    )
