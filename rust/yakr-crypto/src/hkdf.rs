//! HKDF-SHA256 helpers matching `yakr-core` / `yakr-protocol-v1.md`.

use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 expand (default 32-byte output), matching Python `hkdf_derive`.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8], salt: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand to 32 bytes");
    okm
}
