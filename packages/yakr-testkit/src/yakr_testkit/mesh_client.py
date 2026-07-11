from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

import httpx

from yakr_core.crypto import derive_mailbox_secret
from yakr_core.delivery_profile import DeliveryProfile, apply_delivery_profile_update
from yakr_core.errors import DuplicateSeqError, YakrError
from yakr_core.identity import Identity
from yakr_core.message import OuterBlob, message_id
from yakr_core.privacy import fetch_tags_for_mode
from yakr_core.receipt_apply import apply_inbound_delivery_receipt
from yakr_core.session import Session
from yakr_core.store import FileLocalStore
from yakr_cli.network import (
    deliver_encrypted,
    delivery_mailbox_urls,
    fetch_direct_blobs,
    fetch_mailbox_urls,
    fetch_relay_blobs,
)


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
    _send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def send(self, recipient: str, body: str) -> SentMessage:
        with self._send_lock:
            return self._send_unlocked(recipient, body)

    def _send_unlocked(self, recipient: str, body: str) -> SentMessage:
        contact = self.store.get_contact(recipient)
        if contact is None:
            raise ValueError(f"{self.name} has no contact {recipient}")
        session = Session(self.identity, contact)
        encrypted = session.encrypt_text(body)
        self.store.atomic_commit_send(
            contact,
            msg_id=encrypted.msg_id,
            seq=encrypted.inner_message.seq,
            body=body,
            outer=encrypted.outer_blob,
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
        from yakr_cli.network import resend_pending_for_contact

        before = self.store.list_outbound_pending(peer)
        count = resend_pending_for_contact(self.store, self.identity, peer)
        return [
            SentMessage(self.name, peer, body, msg_id, seq)
            for msg_id, seq, body in before[:count]
        ]

    def fetch(
        self,
        peer: str,
        *,
        send_receipts: bool = True,
        save_local: bool = True,
    ) -> list[ReceivedMessage]:
        with self.store.fetch_lock():
            return self._fetch_unlocked(peer, send_receipts=send_receipts, save_local=save_local)

    def _fetch_unlocked(
        self,
        peer: str,
        *,
        send_receipts: bool = True,
        save_local: bool = True,
    ) -> list[ReceivedMessage]:
        from yakr_cli.receipt_cmds import flush_pending_receipts, send_delivery_receipt

        contact = self.store.get_contact(peer)
        if contact is None:
            raise ValueError(f"{self.name} has no contact {peer}")

        flush_pending_receipts(self.store, self.identity, contact_name=peer)

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
                for item in fetch_direct_blobs(
                    tag.tag_b64,
                    direct_hints,
                    store=self.store,
                    contact=contact,
                    identity=self.identity,
                ):
                    items.append((None, item))
            for item in fetch_relay_blobs(
                tag.tag_b64,
                fetch_bases,
                store=self.store,
                contact=contact,
                identity=self.identity,
                timeout=15.0,
            ):
                items.append((None, item))

            seen: set[str] = set()
            queue: list[dict] = []
            for _fetch_base, item in items:
                ciphertext = str(item.get("ciphertext", ""))
                if ciphertext in seen:
                    continue
                seen.add(ciphertext)
                queue.append(item)
            queue.sort(key=lambda blob: int(blob.get("stored_at", 0)))

            pending = list(queue)
            while pending:
                progressed = False
                still_pending: list[dict] = []
                for item in pending:
                    outer = OuterBlob.from_relay_json(item)
                    try:
                        inner = session.decrypt_inbound(outer)
                    except DuplicateSeqError:
                        still_pending.append(item)
                        continue
                    except YakrError:
                        continue
                    progressed = True

                    if inner.type == "profile" and inner.body:
                        profile = DeliveryProfile.from_b64(inner.body)
                        try:
                            apply_delivery_profile_update(
                                contact, profile, contact.signing_public
                            )
                        except ValueError:
                            pass
                        self.store.save_contact(contact)
                        continue

                    from yakr_core.presence import apply_presence_message

                    presence = apply_presence_message(self.store, contact, inner)
                    if presence is not None:
                        self.store.save_contact(contact)
                        continue

                    if inner.type == "receipt" and inner.message_id:
                        apply_inbound_delivery_receipt(self.store, peer, inner)
                        from yakr_core.profile_ack import record_profile_ack_on_receipt

                        record_profile_ack_on_receipt(self.store, contact, peer, inner.message_id)
                        self.store.save_contact(contact)
                        continue

                    if inner.type != "text":
                        continue

                    if save_local:
                        delivered_id = message_id(outer.ciphertext)
                        self.store.atomic_commit_receive_text(
                            contact,
                            inner,
                            identity=self.identity,
                            delivered_id=delivered_id,
                        )
                    else:
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
                        send_delivery_receipt(
                            self.store,
                            self.identity,
                            peer,
                            delivered_id,
                        )
                        persisted = self.store.get_contact(peer)
                        if persisted is not None:
                            contact.next_send_seq = persisted.next_send_seq
                            contact.ratchet = persisted.ratchet
                        self.store.save_contact(contact)
                    else:
                        self._unreceipted.append((peer, outer))
                if not progressed:
                    break
                pending = still_pending

        return received

    def flush_receipts(self, peer: str | None = None) -> int:
        """Send delivery receipts for messages fetched earlier with send_receipts=False."""
        from yakr_cli.receipt_cmds import flush_pending_receipts, send_delivery_receipt

        sent = flush_pending_receipts(self.store, self.identity, contact_name=peer)
        remaining: list[tuple[str, OuterBlob]] = []
        for name, outer in self._unreceipted:
            if peer is not None and name != peer:
                remaining.append((name, outer))
                continue
            if send_delivery_receipt(
                self.store,
                self.identity,
                name,
                message_id(outer.ciphertext),
            ):
                sent += 1
            else:
                remaining.append((name, outer))
        self._unreceipted = remaining
        return sent

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

    def fetch_all(
        self,
        *,
        send_receipts: bool = True,
        save_local: bool = True,
    ) -> dict[str, list[ReceivedMessage]]:
        """Fetch every paired contact (messages + receipts)."""
        from yakr_cli.receipt_cmds import flush_pending_receipts

        flush_pending_receipts(self.store, self.identity)
        received: dict[str, list[ReceivedMessage]] = {}
        for peer in self.store.list_contacts():
            messages = self.fetch(
                peer,
                send_receipts=send_receipts,
                save_local=save_local,
            )
            if messages:
                received[peer] = messages
        return received
