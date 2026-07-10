use std::time::{SystemTime, UNIX_EPOCH};

use yakr_crypto::derive_mailbox_secret;

use crate::ephemeral::{message_valid_until, DEFAULT_BLOB_TTL_MS};
use crate::error::YakrError;
use crate::hybrid_pq::needs_pq_rekey;
use crate::identity::{Contact, Identity};
use crate::mailbox::{MailboxTag, MailboxTagDeriver};
use crate::message::{message_id, OuterBlob};
pub use yakr_crypto::{InnerMessage, MessageType};
use crate::privacy::{decode_padded_plaintext, pad_plaintext};
use crate::ratchet::RatchetState;

pub struct EncryptedMessage {
    pub outer_blob: OuterBlob,
    pub inner_message: InnerMessage,
    pub msg_id: String,
    pub mailbox_tag: MailboxTag,
    pub padding_bytes: usize,
}

pub struct Session {
    pub identity: Identity,
    pub contact: Contact,
}

impl Session {
    pub fn new(identity: Identity, mut contact: Contact) -> Result<Self, YakrError> {
        if contact.ratchet.is_none() {
            return Err(YakrError::Other(
                "contact missing double ratchet state; re-pair required".into(),
            ));
        }
        Ok(Self { identity, contact })
    }

    fn send_direction(&self) -> String {
        direction(&self.identity.name, &self.contact.name)
    }

    fn recv_direction(&self) -> String {
        direction(&self.contact.name, &self.identity.name)
    }

    fn mailbox_deriver(&self, outbound: bool) -> MailboxTagDeriver {
        let direction = if outbound {
            self.send_direction()
        } else {
            self.recv_direction()
        };
        let secret = derive_mailbox_secret(&self.contact.master_secret, &direction);
        MailboxTagDeriver::new(secret, self.contact.mailbox_epoch_secs)
    }

    fn require_fresh_session(&self) -> Result<(), YakrError> {
        if needs_pq_rekey(
            self.contact.hybrid_pq,
            self.contact.session_started_at,
            self.contact.next_send_seq,
        ) {
            return Err(YakrError::RekeyRequired);
        }
        Ok(())
    }

    fn encrypt_inner(&mut self, inner: &InnerMessage) -> Result<(Vec<u8>, usize), YakrError> {
        let raw = inner.to_bytes().map_err(|e| YakrError::Other(e.to_string()))?;
        let mode = self.contact.privacy_mode.clone();
        let (padded, padding_bytes) =
            pad_plaintext(&raw, &mode).map_err(YakrError::Other)?;
        let ratchet = self
            .contact
            .ratchet
            .as_mut()
            .ok_or_else(|| YakrError::Other("missing ratchet".into()))?;
        let ciphertext = ratchet
            .encrypt(&padded)
            .map_err(|e| YakrError::Other(e))?;
        Ok((ciphertext, padding_bytes))
    }

    fn outer_blob(&self, ciphertext: Vec<u8>, tag: MailboxTag) -> OuterBlob {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        OuterBlob {
            version: 1,
            mailbox_tag: tag.tag,
            expires_at: now + DEFAULT_BLOB_TTL_MS,
            ciphertext,
        }
    }

    pub fn encrypt_text(&mut self, body: &str) -> Result<EncryptedMessage, YakrError> {
        self.require_fresh_session()?;
        let seq = self.contact.next_send_seq;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let inner = InnerMessage::text(
            self.contact.conversation_id.clone(),
            self.identity.device_id(),
            seq,
            body,
            now,
            message_valid_until(now),
        );
        let (ciphertext, padding_bytes) = self.encrypt_inner(&inner)?;
        let tag = self
            .mailbox_deriver(true)
            .derive(&self.send_direction(), None);
        let outer = self.outer_blob(ciphertext, tag.clone());
        self.contact.next_send_seq += 1;
        Ok(EncryptedMessage {
            msg_id: message_id(&outer.ciphertext),
            outer_blob: outer,
            inner_message: inner,
            mailbox_tag: tag,
            padding_bytes,
        })
    }

    pub fn decrypt_outer(&mut self, outer: &OuterBlob) -> Result<InnerMessage, YakrError> {
        let mode = self.contact.privacy_mode.clone();
        let ratchet_snapshot = self
            .contact
            .ratchet
            .as_ref()
            .map(|r| r.to_dict())
            .ok_or_else(|| YakrError::Other("missing ratchet".into()))?;
        let last_recv_before = self.contact.last_recv_seq;

        let padded = match self.contact.ratchet.as_mut().unwrap().decrypt(&outer.ciphertext) {
            Err(e) if e.contains("already received") => return Err(YakrError::DuplicateSeq),
            Err(e) => return Err(YakrError::Decrypt(e)),
            Ok(p) => p,
        };

        let plaintext = decode_padded_plaintext(&padded, &mode).map_err(|e| {
            self.restore_ratchet(&ratchet_snapshot);
            YakrError::Decrypt(e)
        })?;

        let inner = InnerMessage::from_bytes(&plaintext)
            .map_err(|e| {
                self.restore_ratchet(&ratchet_snapshot);
                YakrError::Decrypt(e.to_string())
            })?;

        if inner.conversation_id != self.contact.conversation_id {
            self.restore_ratchet(&ratchet_snapshot);
            return Err(YakrError::Decrypt("conversation mismatch".into()));
        }
        if inner.seq <= last_recv_before {
            self.restore_ratchet(&ratchet_snapshot);
            return Err(YakrError::DuplicateSeq);
        }
        if inner.seq != last_recv_before + 1 {
            self.restore_ratchet(&ratchet_snapshot);
            return Err(YakrError::DuplicateSeq);
        }
        if crate::ephemeral::enforce_message_ttl(inner.valid_until).is_err() {
            self.restore_ratchet(&ratchet_snapshot);
            return Err(YakrError::MessageExpired);
        }
        self.contact.last_recv_seq = inner.seq;
        Ok(inner)
    }

    fn restore_ratchet(&mut self, snapshot: &crate::ratchet::RatchetDict) {
        if let Ok(r) = RatchetState::from_dict(snapshot) {
            self.contact.ratchet = Some(r);
        }
    }

    pub fn into_contact(self) -> Contact {
        self.contact
    }
}

fn direction(sender: &str, recipient: &str) -> String {
    format!("{sender}->{recipient}")
}
