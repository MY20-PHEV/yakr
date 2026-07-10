//! Mailbox secret and tag derivation (`yakr-protocol-v1.md` §3.6).

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::hkdf::hkdf_sha256;

/// Domain separation prefix for per-direction mailbox secrets.
pub const MAILBOX_TAG_INFO: &[u8] = b"yakr/v0.1/mailbox-tag";

type HmacSha256 = Hmac<Sha256>;

/// Derive the mailbox HMAC key for a pairwise direction string.
pub fn derive_mailbox_secret(master_secret: &[u8], direction: &str) -> [u8; 32] {
    let mut info = Vec::with_capacity(MAILBOX_TAG_INFO.len() + direction.len());
    info.extend_from_slice(MAILBOX_TAG_INFO);
    info.extend_from_slice(direction.as_bytes());
    hkdf_sha256(master_secret, &info, b"")
}

/// Compute the mailbox tag for `(direction, epoch)`.
pub fn derive_mailbox_tag(
    master_secret: &[u8],
    direction: &str,
    epoch: u64,
) -> [u8; 32] {
    let mailbox_secret = derive_mailbox_secret(master_secret, direction);
    let material = format!("{direction}|{epoch}");
    let mut mac =
        HmacSha256::new_from_slice(&mailbox_secret).expect("HMAC accepts 32-byte key");
    mac.update(material.as_bytes());
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct MailboxTagVector {
        name: String,
        master_secret_hex: String,
        direction: String,
        epoch: u64,
        #[allow(dead_code)]
        epoch_secs: u64,
        expected_tag_hex: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn mailbox_tag_vector() {
        let path = vectors_path("mailbox_tag.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vector: MailboxTagVector =
            serde_json::from_str(&raw).expect("parse mailbox_tag.json");

        let master_secret = hex::decode(&vector.master_secret_hex).expect("master_secret");
        let expected_tag = hex::decode(&vector.expected_tag_hex).expect("expected_tag");

        let tag = derive_mailbox_tag(&master_secret, &vector.direction, vector.epoch);

        assert_eq!(
            tag.as_slice(),
            expected_tag.as_slice(),
            "vector {} tag mismatch",
            vector.name
        );
    }
}
