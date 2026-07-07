from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization

from yakr_core.crypto import derive_mailbox_secret, hkdf_derive, xchacha_decrypt, xchacha_encrypt
from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.ephemeral import DEFAULT_BLOB_TTL_MS, enforce_message_ttl
from yakr_core.errors import DecryptError, DuplicateSeqError, MessageExpiredError, RekeyRequiredError
from yakr_core.hybrid_pq import needs_pq_rekey
from yakr_core.identity import Contact, Identity
from yakr_core.mailbox import MailboxTag, MailboxTagDeriver
from yakr_core.message import InnerMessage, OuterBlob, message_id
from yakr_core.privacy import decode_padded_plaintext, pad_plaintext


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
        if contact.ratchet is None:
            raise ValueError("contact missing double ratchet state; re-pair required")

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

    def _message_aad(self, inner: InnerMessage) -> bytes:
        return aad_for_message(
            valid_until=inner.valid_until,
            conversation_id=inner.conversation_id,
            seq=inner.seq,
        )

    def _encrypt_inner(self, inner: InnerMessage) -> tuple[bytes, int]:
        raw = inner.to_bytes()
        padded, padding_bytes = pad_plaintext(raw, self.contact.privacy_mode)
        ratchet_payload = self.contact.ratchet.encrypt(padded)
        return ratchet_payload, padding_bytes

    def _outer_blob(self, ciphertext: bytes, tag: MailboxTag) -> OuterBlob:
        return OuterBlob(
            version=1,
            mailbox_tag=tag.tag,
            expires_at=int(time.time() * 1000) + DEFAULT_BLOB_TTL_MS,
            ciphertext=ciphertext,
        )

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
        outer = self._outer_blob(ciphertext, tag)
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(outer.ciphertext),
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
        outer = self._outer_blob(ciphertext, tag)
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(outer.ciphertext),
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
        outer = self._outer_blob(ciphertext, tag)
        self.contact.next_send_seq += 1
        return EncryptedMessage(
            outer_blob=outer,
            inner_message=inner,
            msg_id=message_id(outer.ciphertext),
            mailbox_tag=tag,
            padding_bytes=padding_bytes,
        )

    def decrypt_outer(self, outer: OuterBlob) -> InnerMessage:
        mode = self.contact.privacy_mode
        try:
            padded = self.contact.ratchet.decrypt(outer.ciphertext)
        except ValueError as exc:
            if "already received" in str(exc):
                raise DuplicateSeqError("duplicate message") from exc
            raise DecryptError("unable to decrypt blob") from exc
        except Exception as exc:
            raise DecryptError("unable to decrypt blob") from exc
        try:
            plaintext = decode_padded_plaintext(padded, mode)
        except ValueError as exc:
            raise DecryptError("invalid padded plaintext") from exc
        inner = InnerMessage.from_bytes(plaintext)
        if inner.conversation_id != self.contact.conversation_id:
            raise DecryptError("conversation mismatch")
        if inner.seq <= self.contact.last_recv_seq:
            raise DuplicateSeqError(f"duplicate seq {inner.seq}")
        try:
            enforce_message_ttl(inner.valid_until)
        except MessageExpiredError:
            raise
        self.contact.last_recv_seq = inner.seq
        return inner

    def _require_fresh_session(self) -> None:
        if needs_pq_rekey(
            hybrid=self.contact.hybrid_pq,
            session_started_at_ms=self.contact.session_started_at,
            messages_sent=self.contact.next_send_seq,
        ):
            raise RekeyRequiredError("PQ session rekey required")


def _direction(sender: str, recipient: str) -> str:
    return f"{sender}->{recipient}"


def device_storage_key(identity: Identity) -> bytes:
    from yakr_core.crypto import hkdf_derive

    private_bytes = identity.signing_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return hkdf_derive(private_bytes, b"yakr/v1.0/local-message-store")


def wrap_local_ciphertext(identity: Identity, outer_ciphertext: bytes) -> bytes:
    from yakr_core.crypto import xchacha_encrypt

    return xchacha_encrypt(device_storage_key(identity), outer_ciphertext)


def unwrap_local_ciphertext(identity: Identity, payload: bytes) -> bytes:
    from yakr_core.crypto import xchacha_decrypt

    return xchacha_decrypt(device_storage_key(identity), payload)
