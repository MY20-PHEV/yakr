from __future__ import annotations

import os
from dataclasses import dataclass, field

import httpx

from yakr_core.crypto import derive_mailbox_secret
from yakr_core.delivery_profile import DeliveryProfile, verify_delivery_profile
from yakr_core.errors import DuplicateSeqError, YakrError
from yakr_core.identity import Identity
from yakr_core.message import OuterBlob, message_id
from yakr_core.privacy import fetch_tags_for_mode
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import deliver_encrypted, fetch_direct_blobs, fetch_mailbox_urls


@dataclass
class ReceivedMessage:
    sender: str
    body: str
    seq: int
    valid_until: int


@dataclass
class SentMessage:
    sender: str
    recipient: str
    body: str
    msg_id: str
    seq: int


@dataclass
class MeshParticipant:
    name: str
    identity: Identity
    store: FileLocalStore
    relay_url: str
    sent: list[SentMessage] = field(default_factory=list)
    _unreceipted: list[tuple[str, OuterBlob]] = field(default_factory=list)

    def send(self, recipient: str, body: str) -> SentMessage:
        contact = self.store.get_contact(recipient)
        if contact is None:
            raise ValueError(f"{self.name} has no contact {recipient}")
        session = Session(self.identity, contact)
        encrypted = session.encrypt_text(body)
        self.store.save_contact(contact)
        self.store.save_outbound_pending(
            recipient,
            encrypted.msg_id,
            encrypted.inner_message.seq,
            body,
        )
        previous = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = self.relay_url
        try:
            deliver_encrypted(
                encrypted,
                contact=contact,
                identity=self.identity,
                store=self.store,
                allow_direct=False,
            )
        finally:
            if previous is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous
        record = SentMessage(
            sender=self.name,
            recipient=recipient,
            body=body,
            msg_id=encrypted.msg_id,
            seq=encrypted.inner_message.seq,
        )
        self.sent.append(record)
        return record

    def try_send(self, recipient: str, body: str) -> tuple[SentMessage | None, BaseException | None]:
        try:
            return self.send(recipient, body), None
        except BaseException as exc:
            return None, exc

    def try_fetch(
        self,
        peer: str,
        *,
        send_receipts: bool = True,
        save_local: bool = True,
    ) -> tuple[list[ReceivedMessage] | None, BaseException | None]:
        try:
            return self.fetch(peer, send_receipts=send_receipts, save_local=save_local), None
        except BaseException as exc:
            return None, exc

    def resend_pending(self, peer: str) -> list[SentMessage]:
        """Re-encrypt and deliver each pending outbound message (new seq each time)."""
        resent: list[SentMessage] = []
        for msg_id, _seq, body in list(self.store.list_outbound_pending(peer)):
            record = self.send(peer, body)
            self.store.mark_outbound_delivered(peer, msg_id)
            resent.append(record)
        return resent

    def fetch(
        self,
        peer: str,
        *,
        send_receipts: bool = True,
        save_local: bool = True,
    ) -> list[ReceivedMessage]:
        contact = self.store.get_contact(peer)
        if contact is None:
            raise ValueError(f"{self.name} has no contact {peer}")

        self.store.sweep_expired_messages()
        self.store.sweep_expired_outbound()

        session = Session(self.identity, contact)
        deriver = session.mailbox_deriver(outbound=False)
        mailbox_secret = derive_mailbox_secret(contact.master_secret, session.recv_direction)
        tags = fetch_tags_for_mode(
            deriver,
            session.recv_direction,
            contact.privacy_mode,
            mailbox_secret=mailbox_secret,
        )
        previous_relay = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = self.relay_url
        try:
            fetch_bases = fetch_mailbox_urls(contact, None, store=self.store)
        finally:
            if previous_relay is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous_relay
        direct_hints = list(contact.delivery_profile.direct_hints) if contact.delivery_profile else []

        received: list[ReceivedMessage] = []
        for tag in tags:
            items: list[tuple[str | None, dict]] = []
            if direct_hints:
                for item in fetch_direct_blobs(tag.tag_b64, direct_hints):
                    items.append((None, item))
            for fetch_base in fetch_bases:
                response = httpx.get(f"{fetch_base}/v1/blobs/{tag.tag_b64}", timeout=15.0)
                if response.status_code != 200:
                    raise YakrError(f"relay fetch failed: {response.status_code}")
                for item in response.json():
                    items.append((fetch_base, item))

            seen: set[str] = set()
            for _fetch_base, item in items:
                ciphertext = str(item.get("ciphertext", ""))
                if ciphertext in seen:
                    continue
                seen.add(ciphertext)
                outer = OuterBlob.from_relay_json(item)
                try:
                    inner = session.decrypt_outer(outer)
                except DuplicateSeqError:
                    continue
                except YakrError:
                    continue

                if inner.type == "profile" and inner.body:
                    profile = DeliveryProfile.from_b64(inner.body)
                    verify_delivery_profile(profile, contact.signing_public)
                    contact.delivery_profile = profile
                    self.store.save_contact(contact)
                    continue

                if inner.type == "receipt" and inner.message_id:
                    self.store.mark_outbound_delivered(peer, inner.message_id)
                    continue

                if inner.type != "text":
                    continue

                if save_local:
                    self.store.save_inbound_message(peer, inner, identity=self.identity)
                self.store.save_contact(contact)
                received.append(
                    ReceivedMessage(
                        sender=peer,
                        body=inner.body,
                        seq=inner.seq,
                        valid_until=inner.valid_until,
                    )
                )

                if send_receipts:
                    try:
                        self._send_receipt(session, contact, outer)
                    except BaseException:
                        self._unreceipted.append((peer, outer))
                else:
                    self._unreceipted.append((peer, outer))

        return received

    def flush_receipts(self, peer: str | None = None) -> int:
        """Send delivery receipts for messages fetched earlier with send_receipts=False."""
        sent = 0
        remaining: list[tuple[str, OuterBlob]] = []
        for name, outer in self._unreceipted:
            if peer is not None and name != peer:
                remaining.append((name, outer))
                continue
            contact = self.store.get_contact(name)
            if contact is None:
                continue
            session = Session(self.identity, contact)
            try:
                self._send_receipt(session, contact, outer)
                sent += 1
            except BaseException:
                remaining.append((name, outer))
        self._unreceipted = remaining
        return sent

    def _send_receipt(self, session: Session, contact, outer: OuterBlob) -> None:
        receipt = session.encrypt_receipt(message_id(outer.ciphertext))
        self.store.save_contact(contact)
        previous = os.environ.get("YAKR_RELAY_URL")
        os.environ["YAKR_RELAY_URL"] = self.relay_url
        try:
            deliver_encrypted(
                receipt,
                contact=contact,
                identity=self.identity,
                store=self.store,
                allow_direct=False,
            )
        finally:
            if previous is None:
                os.environ.pop("YAKR_RELAY_URL", None)
            else:
                os.environ["YAKR_RELAY_URL"] = previous

    def pending_count(self, peer: str | None = None) -> int:
        if peer is None:
            total = 0
            for name in self.store.list_contacts():
                total += len(self.store.list_outbound_pending(name))
            return total
        return len(self.store.list_outbound_pending(peer))

    def drain_receipts(self) -> int:
        """Poll contacts for inbound delivery receipts."""
        for peer in self.store.list_contacts():
            self.fetch(peer, send_receipts=False, save_local=False)
        return self.pending_count()
