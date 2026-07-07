from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

import httpx

from yakr_core.crypto import derive_mailbox_secret
from yakr_core.delivery_profile import DeliveryProfile, verify_delivery_profile
from yakr_core.errors import YakrError
from yakr_core.identity import Identity
from yakr_core.invite import invite_from_url, verify_invite
from yakr_core.message import OuterBlob
from yakr_core.pairing import (
    OFFLINE_RENDEZVOUS_HINT,
    PairingResponse,
    PairingSecrets,
    build_offline_pairing_request,
    build_pairing_request,
    finish_offline_pairing,
    joiner_complete_pairing,
    pair_request_from_url,
    pending_session_from_request,
    respond_to_pair_request,
)
from yakr_core.privacy import fetch_tags_for_mode
from yakr_core.session import Session

from yakr_mobile.device_settings import DeviceSettings, fetch_poll_interval, relay_may_run
from yakr_mobile.encrypted_store import MobileStore
from yakr_mobile.invite_qr import InvitePresentation, QrPayload, build_invite_presentation, build_qr_payload


@dataclass
class SendResult:
    mode: str
    seq: int


@dataclass
class FetchResult:
    contact_name: str
    messages: list[str]
    fetched_count: int


class YakrMobileClient:
    def __init__(self, store: MobileStore, *, relay_url: str) -> None:
        self.store = store
        self.relay_url = relay_url.rstrip("/")

    def init_identity(self, name: str) -> Identity:
        identity = Identity.generate(name)
        self.store.save_identity(identity)
        return identity

    def load_identity(self) -> Identity | None:
        return self.store.load_identity()

    def create_invite(
        self,
        *,
        rendezvous_hint: str | None = None,
        hybrid_pq: bool = False,
        offline: bool = False,
    ) -> InvitePresentation:
        identity = self._require_identity()
        hint = OFFLINE_RENDEZVOUS_HINT if offline else (rendezvous_hint or "http://127.0.0.1:8090")
        return build_invite_presentation(
            identity,
            rendezvous_hint=hint,
            hybrid_pq=hybrid_pq,
        )

    def start_offline_pairing(self, invite_url: str) -> QrPayload:
        identity = self._require_identity()
        bundle = invite_from_url(invite_url)
        verify_invite(bundle)
        profile = self.store.file_store.load_local_profile()
        if profile is None:
            from yakr_cli.profile_cmds import build_local_profile

            profile = build_local_profile(identity, store=self.store.file_store)
            self.store.file_store.save_local_profile(profile)
        request, secrets, request_url = build_offline_pairing_request(
            identity,
            bundle,
            joiner_name=identity.name,
            joiner_profile=profile.to_bytes(),
        )
        session = pending_session_from_request(invite_url, request, secrets)
        self.store.file_store.save_pending_pairing(session)
        return build_qr_payload(request_url)

    def respond_offline_pairing(self, invite_url: str, request_url: str):
        identity = self._require_identity()
        bundle = invite_from_url(invite_url)
        request = pair_request_from_url(request_url)
        profile = self.store.file_store.load_local_profile()
        if profile is None:
            from yakr_cli.profile_cmds import build_local_profile

            profile = build_local_profile(identity, store=self.store.file_store)
            self.store.file_store.save_local_profile(profile)
        _, contact, response_url = respond_to_pair_request(
            identity,
            bundle,
            request,
            inviter_profile=profile.to_bytes(),
        )
        self.store.save_contact(contact)
        return contact, build_qr_payload(response_url)

    def finish_offline_pairing(self, response_url: str, *, contact_name: str | None = None):
        identity = self._require_identity()
        session = self.store.file_store.load_pending_pairing()
        if session is None:
            raise YakrError("no pending offline pairing session")
        bundle = invite_from_url(session.invite_url)
        request = pair_request_from_url(session.request_url)
        contact = finish_offline_pairing(
            identity,
            bundle,
            request,
            session.secrets(),
            response_url,
            contact_name=contact_name,
        )
        self.store.save_contact(contact)
        self.store.file_store.clear_pending_pairing()
        return contact

    def complete_pairing_as_joiner(
        self,
        invite_url: str,
        pairing_response: PairingResponse,
        secrets: PairingSecrets,
        *,
        joiner_name: str | None = None,
    ):
        identity = self._require_identity()
        bundle = invite_from_url(invite_url)
        verify_invite(bundle)
        request, _ = build_pairing_request(identity, bundle, joiner_name=joiner_name or identity.name)
        contact = joiner_complete_pairing(identity, bundle, request, secrets, pairing_response)
        contact.name = joiner_name or bundle.inviter_name
        self.store.save_contact(contact)
        return contact

    def send_text(self, contact_name: str, body: str) -> SendResult:
        identity = self._require_identity()
        contact = self._require_contact(contact_name)
        session = Session(identity, contact)
        encrypted = session.encrypt_text(body)
        self.store.save_contact(contact)
        self.store.save_outbound_pending(contact_name, encrypted.msg_id, encrypted.inner_message.seq, body)

        previous = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = self.relay_url
        try:
            from yakr_cli.network import deliver_encrypted

            mode = deliver_encrypted(
                encrypted,
                contact=contact,
                identity=identity,
                store=self.store.file_store,
            )
        finally:
            if previous is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous

        metrics = self.store.load_privacy_metrics()
        metrics.record_send(len(encrypted.outer_blob.ciphertext), padding_bytes=encrypted.padding_bytes)
        self.store.save_privacy_metrics(metrics)
        return SendResult(mode=mode, seq=encrypted.inner_message.seq)

    def fetch_contact(self, contact_name: str) -> FetchResult:
        from yakr_cli.network import (
            deliver_encrypted,
            fetch_direct_blobs,
            fetch_mailbox_urls,
            resolve_contact_route,
        )
        from yakr_core.message import message_id

        identity = self._require_identity()
        contact = self._require_contact(contact_name)
        session = Session(identity, contact)
        self.store.sweep_expired_messages()
        self.store.sweep_expired_outbound()
        deriver = session.mailbox_deriver(outbound=False)
        mailbox_secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)
        tags = fetch_tags_for_mode(
            deriver,
            session.recv_direction,
            contact.privacy_mode,
            mailbox_secret=mailbox_secret,
        )
        real_tags = {tag.tag_b64 for tag in deriver.candidate_epochs(session.recv_direction)}
        resolved_route = resolve_contact_route(self.store.file_store, contact, None, "fetch")
        previous = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = self.relay_url
        try:
            fetch_bases = fetch_mailbox_urls(contact, resolved_route, store=self.store.file_store)
        finally:
            if previous is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous
        direct_hints = list(contact.delivery_profile.direct_hints) if contact.delivery_profile else []

        messages: list[str] = []
        metrics = self.store.load_privacy_metrics()
        for tag in tags:
            is_decoy = tag.tag_b64 not in real_tags
            items: list[tuple[str | None, dict]] = []
            if direct_hints:
                for item in fetch_direct_blobs(tag.tag_b64, direct_hints):
                    items.append((None, item))
            for fetch_base in fetch_bases:
                response = httpx.get(f"{fetch_base}/v1/blobs/{tag.tag_b64}", timeout=10.0)
                if response.status_code != 200:
                    raise YakrError(f"relay fetch failed: {response.status_code}")
                for item in response.json():
                    items.append((fetch_base, item))
                metrics.record_fetch(len(response.content), decoy=is_decoy)

            seen: set[str] = set()
            for fetch_base, item in items:
                ciphertext = str(item.get("ciphertext", ""))
                if ciphertext in seen:
                    continue
                seen.add(ciphertext)
                outer = OuterBlob.from_relay_json(item)
                try:
                    inner = session.decrypt_outer(outer)
                except YakrError:
                    continue
                if inner.type == "profile" and inner.body:
                    profile = DeliveryProfile.from_b64(inner.body)
                    verify_delivery_profile(profile, contact.signing_public)
                    contact.delivery_profile = profile
                    self.store.save_contact(contact)
                    continue
                if inner.type == "receipt":
                    if inner.message_id:
                        self.store.mark_outbound_delivered(contact_name, inner.message_id)
                    continue
                if inner.type != "text":
                    continue
                self.store.save_inbound_message(contact_name, inner, identity=identity)
                self.store.save_contact(contact)
                messages.append(inner.body)
                receipt = session.encrypt_receipt(message_id(outer.ciphertext))
                self.store.save_contact(contact)
                previous = os.environ.get("YAKR_RELAY_URL")
                os.environ["YAKR_RELAY_URL"] = self.relay_url
                try:
                    deliver_encrypted(
                        receipt,
                        contact=contact,
                        identity=identity,
                        store=self.store.file_store,
                        allow_direct=False,
                    )
                finally:
                    if previous is None:
                        os.environ.pop("YAKR_RELAY_URL", None)
                    else:
                        os.environ["YAKR_RELAY_URL"] = previous

        self.store.save_privacy_metrics(metrics)
        self.store.save_worker_state("last_fetch_at", str(int(time.time())))
        self.store.save_worker_state(
            "last_fetch_contacts",
            json.dumps(self._update_last_fetch_contacts(contact_name)),
        )
        return FetchResult(contact_name=contact_name, messages=messages, fetched_count=len(messages))

    def resume_state(self) -> dict[str, object]:
        return {
            "last_fetch_at": self.store.load_worker_state("last_fetch_at"),
            "last_fetch_contacts": json.loads(
                self.store.load_worker_state("last_fetch_contacts", "[]")
            ),
            "pending": [
                contact
                for contact in self.store.list_contacts()
                if self.store.list_outbound_pending(contact)
            ],
        }

    def _update_last_fetch_contacts(self, contact_name: str) -> list[str]:
        raw = self.store.load_worker_state("last_fetch_contacts", "[]")
        contacts = json.loads(raw)
        if contact_name not in contacts:
            contacts.append(contact_name)
        return contacts

    def _require_identity(self) -> Identity:
        identity = self.store.load_identity()
        if identity is None:
            raise YakrError("identity not initialized")
        return identity

    def _require_contact(self, name: str):
        contact = self.store.get_contact(name)
        if contact is None:
            raise YakrError(f"unknown contact: {name}")
        return contact


class FetchWorker:
    def __init__(self, client: YakrMobileClient, settings: DeviceSettings) -> None:
        self.client = client
        self.settings = settings
        self._last_poll_at = 0.0

    @property
    def poll_interval_secs(self) -> int:
        return fetch_poll_interval(self.settings)

    def should_poll(self, *, now: float | None = None) -> bool:
        now_value = time.time() if now is None else now
        return now_value - self._last_poll_at >= self.poll_interval_secs

    def poll_all(self, *, now: float | None = None) -> list[FetchResult]:
        now_value = time.time() if now is None else now
        if not self.should_poll(now=now_value):
            return []
        self._last_poll_at = now_value
        return [self.client.fetch_contact(name) for name in self.client.store.list_contacts()]


class RelayWorker:
    def __init__(self, settings: DeviceSettings) -> None:
        self.settings = settings
        self.running = False

    def should_run(self) -> bool:
        return relay_may_run(self.settings)

    def start(self) -> bool:
        if not self.should_run():
            self.running = False
            return False
        self.running = True
        return True

    def stop(self) -> None:
        self.running = False
