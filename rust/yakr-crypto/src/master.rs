//! Classical pairwise master and message-key derivation (`yakr-protocol-v1.md` §3.3).

use crate::hkdf::hkdf_sha256;

/// Domain separation for classical pairwise master (`yakr/v0.1/master`).
pub const MASTER_INFO: &[u8] = b"yakr/v0.1/master";
/// Domain separation for per-message keys (`yakr/v0.1/message-key`).
pub const MESSAGE_KEY_INFO: &[u8] = b"yakr/v0.1/message-key";

/// HKDF-SHA256 classical master from an X25519 shared secret.
pub fn derive_master_secret(shared_secret: &[u8], salt: &[u8]) -> [u8; 32] {
    hkdf_sha256(shared_secret, MASTER_INFO, salt)
}

/// Per-sequence message key from pairwise master.
pub fn derive_message_key(master_secret: &[u8], seq: u64) -> [u8; 32] {
    let mut info = Vec::with_capacity(MESSAGE_KEY_INFO.len() + 8);
    info.extend_from_slice(MESSAGE_KEY_INFO);
    info.extend_from_slice(&seq.to_be_bytes());
    hkdf_sha256(master_secret, &info, b"")
}
