from __future__ import annotations

import time
from dataclasses import dataclass

from yakr_core.crypto import derive_mailbox_secret, derive_message_key, xchacha_decrypt, xchacha_encrypt
from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.errors import DecryptError, DuplicateSeqError
from yakr_core.identity import Contact, Identity
from yakr_core.mailbox import MailboxTag, MailboxTagDeriver
from yakr_core.message import InnerMessage, OuterBlob, message_id


DEFAULT_BLOB_TTL_MS = 7 * 24 * 60 * 60 * 1000


@dataclass
class EncryptedMessage:
    outer_blob: OuterBlob
    inner_message: InnerMessage
    msg_id: str
    mailbox_tag: MailboxTag


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

    def _encrypt_inner(self, inner: InnerMessage) -> bytes:
        if self.contact.ratchet is not None:
            return self.contact.ratchet.encrypt(inner.to_bytes())
        key = derive_message_key(self.contact.master_secret, inner.seq)
        return xchacha_encrypt(key, inner.to_bytes())

    def encrypt_text(self, body: str) -> EncryptedMessage:
        seq = self.contact.next_send_seq
        inner = InnerMessage.text(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            body=body,
        )
        ciphertext = self._encrypt_inner(inner)
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
        )

    def encrypt_receipt(self, delivered_message_id: str) -> EncryptedMessage:
        seq = self.contact.next_send_seq
        inner = InnerMessage.receipt(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            message_id=delivered_message_id,
        )
        ciphertext = self._encrypt_inner(inner)
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
        )

    def encrypt_profile(self, profile: DeliveryProfile) -> EncryptedMessage:
        seq = self.contact.next_send_seq
        inner = InnerMessage.profile(
            conversation_id=self.contact.conversation_id,
            sender_device_id=self.identity.device_id,
            seq=seq,
            profile_b64=profile.to_b64(),
        )
        ciphertext = self._encrypt_inner(inner)
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
        )

    def decrypt_outer(self, outer: OuterBlob) -> InnerMessage:
        if self.contact.ratchet is not None:
            for offset in range(10):
                seq_hint = self.contact.ratchet.recv_n + offset
                try:
                    plaintext = self.contact.ratchet.decrypt_at(outer.ciphertext, seq_hint=seq_hint)
                except Exception:
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
                plaintext = xchacha_decrypt(key, outer.ciphertext)
            except Exception:
                continue
            inner = InnerMessage.from_bytes(plaintext)
            if inner.conversation_id != self.contact.conversation_id:
                raise DecryptError("conversation mismatch")
            if inner.seq <= self.contact.last_recv_seq:
                raise DuplicateSeqError(f"duplicate seq {inner.seq}")
            self.contact.last_recv_seq = inner.seq
            return inner
        raise DecryptError("unable to decrypt blob")


def _direction(sender: str, recipient: str) -> str:
    return f"{sender}->{recipient}"
