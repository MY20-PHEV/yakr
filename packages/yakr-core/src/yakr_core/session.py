from __future__ import annotations

import time
from dataclasses import dataclass

from yakr_core.crypto import derive_mailbox_secret, derive_message_key, xchacha_decrypt, xchacha_encrypt
from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.hybrid_pq import needs_pq_rekey
from yakr_core.errors import DecryptError, DuplicateSeqError, RekeyRequiredError
from yakr_core.identity import Contact, Identity
from yakr_core.mailbox import MailboxTag, MailboxTagDeriver
from yakr_core.message import InnerMessage, OuterBlob, message_id
from yakr_core.privacy import PrivacyMetrics, decode_padded_plaintext, pad_plaintext


DEFAULT_BLOB_TTL_MS = 7 * 24 * 60 * 60 * 1000


@dataclass
class EncryptedMessage:
    outer_blob: OuterBlob
    inner_message: InnerMessage
    msg_id: str
    mailbox_tag: MailboxTag
    padding_bytes: int = 0


class Session:
    def __init__(self, identity: Identity, contact: Contact) -> None:
        self.identity = identity
        self.contact = contact

    @property
    def send_direction(self) -> str:
        return _direction(self.identity.name, self.contact.name)

    @property
    def recv_direction(self) -> str:
        return _direction(self.contact.name, self.identity.name)

    def mailbox_deriver(self, *, outbound: bool) -> MailboxTagDeriver:
        direction = self.send_direction if outbound else self.recv_direction
        secret = derive_mailbox_secret(self.contact.master_secret, direction)
        epoch_secs = 3600
        if self.contact.delivery_profile is not None:
            epoch_secs = self.contact.delivery_profile.mailbox_epoch_secs
        return MailboxTagDeriver(secret, epoch_secs=epoch_secs)

    def _encrypt_inner(self, inner: InnerMessage) -> tuple[bytes, int]:
        raw = inner.to_bytes()
        padded, padding_bytes = pad_plaintext(raw, self.contact.privacy_mode)
        if self.contact.ratchet is not None:
            return self.contact.ratchet.encrypt(padded), padding_bytes
        key = derive_message_key(self.contact.master_secret, inner.seq)
        return xchacha_encrypt(key, padded), padding_bytes

    def encrypt_text(self, body: str) -> EncryptedMessage:
        self._require_fresh_session()
        seq = self.contact.next_send_seq
        inner = InnerMessage.text(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            body=body,
        )
        ciphertext, padding_bytes = self._encrypt_inner(inner)
        tag = self.mailbox_deriver(outbound=True).derive(self.send_direction)
        outer = OuterBlob(
            version=1,
            mailbox_tag=tag.tag,
            expires_at=int(time.time() * 1000) + DEFAULT_BLOB_TTL_MS,
            ciphertext=ciphertext,
        )
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(ciphertext),
            mailbox_tag=tag,
            padding_bytes=padding_bytes,
        )

    def encrypt_receipt(self, delivered_message_id: str) -> EncryptedMessage:
        self._require_fresh_session()
        seq = self.contact.next_send_seq
        inner = InnerMessage.receipt(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            message_id=delivered_message_id,
        )
        ciphertext, padding_bytes = self._encrypt_inner(inner)
        tag = self.mailbox_deriver(outbound=True).derive(self.send_direction)
        outer = OuterBlob(
            version=1,
            mailbox_tag=tag.tag,
            expires_at=int(time.time() * 1000) + DEFAULT_BLOB_TTL_MS,
            ciphertext=ciphertext,
        )
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(ciphertext),
            mailbox_tag=tag,
            padding_bytes=padding_bytes,
        )

    def encrypt_profile(self, profile: DeliveryProfile) -> EncryptedMessage:
        self._require_fresh_session()
        seq = self.contact.next_send_seq
        inner = InnerMessage.profile(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            profile_b64=profile.to_b64(),
        )
        ciphertext, padding_bytes = self._encrypt_inner(inner)
        tag = self.mailbox_deriver(outbound=True).derive(self.send_direction)
        outer = OuterBlob(
            version=1,
            mailbox_tag=tag.tag,
            expires_at=int(time.time() * 1000) + DEFAULT_BLOB_TTL_MS,
            ciphertext=ciphertext,
        )
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(ciphertext),
            mailbox_tag=tag,
            padding_bytes=padding_bytes,
        )

    def decrypt_outer(self, outer: OuterBlob) -> InnerMessage:
        mode = self.contact.privacy_mode
        if self.contact.ratchet is not None:
            for offset in range(10):
                seq_hint = self.contact.ratchet.recv_n + offset
                try:
                    padded = self.contact.ratchet.decrypt_at(outer.ciphertext, seq_hint=seq_hint)
                except Exception:
                    continue
                try:
                    plaintext = decode_padded_plaintext(padded, mode)
                except ValueError:
                    continue
                inner = InnerMessage.from_bytes(plaintext)
                if inner.conversation_id != self.contact.conversation_id:
                    raise DecryptError("conversation mismatch")
                if inner.seq <= self.contact.last_recv_seq:
                    raise DuplicateSeqError(f"duplicate seq {inner.seq}")
                self.contact.ratchet.commit_recv(seq_hint)
                self.contact.last_recv_seq = inner.seq
                return inner
            raise DecryptError("unable to decrypt blob")

        for seq in range(max(1, self.contact.last_recv_seq), self.contact.next_send_seq + 5):
            key = derive_message_key(self.contact.master_secret, seq)
            try:
                padded = xchacha_decrypt(key, outer.ciphertext)
            except Exception:
                continue
            try:
                plaintext = decode_padded_plaintext(padded, mode)
            except ValueError:
                continue
            inner = InnerMessage.from_bytes(plaintext)
            if inner.conversation_id != self.contact.conversation_id:
                raise DecryptError("conversation mismatch")
            if inner.seq <= self.contact.last_recv_seq:
                raise DuplicateSeqError(f"duplicate seq {inner.seq}")
            self.contact.last_recv_seq = inner.seq
            return inner
        raise DecryptError("unable to decrypt blob")

    def _require_fresh_session(self) -> None:
        if needs_pq_rekey(
            hybrid=self.contact.hybrid_pq,
            session_started_at_ms=self.contact.session_started_at,
            messages_sent=self.contact.next_send_seq,
        ):
            raise RekeyRequiredError("PQ session rekey required")


def _direction(sender: str, recipient: str) -> str:
    return f"{sender}->{recipient}"
