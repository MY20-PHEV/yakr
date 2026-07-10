//! XChaCha20-Poly1305 AEAD matching Python `nacl` bindings.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;

/// Encrypt with a random 24-byte nonce prepended (Python `xchacha_encrypt`).
pub fn xchacha_encrypt(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, AeadError> {
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
    let mut nonce = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| AeadError::EncryptFailed)?;
    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt payload with leading 24-byte nonce (Python `xchacha_decrypt`).
pub fn xchacha_decrypt(key: &[u8], payload: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, AeadError> {
    if payload.len() < 24 {
        return Err(AeadError::CiphertextTooShort);
    }
    let (nonce, ciphertext) = payload.split_at(24);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKey)?;
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| AeadError::DecryptFailed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    InvalidKey,
    CiphertextTooShort,
    EncryptFailed,
    DecryptFailed,
}
