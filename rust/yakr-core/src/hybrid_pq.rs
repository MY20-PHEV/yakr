//! ML-KEM-768 hybrid post-quantum helpers.

#![allow(deprecated)]

use ml_kem::{
    array::Array,
    kem::{Decapsulate, Encapsulate, Generate, KeyExport, Kem, TryKeyInit},
    Ciphertext, DecapsulationKey, EncapsulationKey, ExpandedKeyEncoding, MlKem768,
};

pub const HYBRID_PQ_CAPABILITY: &str = "hybrid_pq";
pub const PQ_REKEY_MAX_MESSAGES: u64 = 10_000;
pub const PQ_REKEY_MAX_AGE_MS: u64 = 7 * 24 * 60 * 60 * 1000;

// ML-KEM-768 sizes (FIPS 203 / Python `pqcrypto.kem.ml_kem_768`).
pub const KEM_PUBLIC_KEY_SIZE: usize = 1184;
pub const KEM_SECRET_KEY_SIZE: usize = 2400;
pub const KEM_CIPHERTEXT_SIZE: usize = 1088;
pub const KEM_SHARED_SECRET_SIZE: usize = 32;

pub fn kem_generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate_keypair();
    (
        ek.to_bytes().as_slice().to_vec(),
        dk.to_expanded_bytes().as_slice().to_vec(),
    )
}

pub fn kem_encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if public_key.len() != KEM_PUBLIC_KEY_SIZE {
        return Err("invalid ML-KEM-768 public key length".into());
    }
    let key = Array::<u8, _>::clone_from_slice(public_key);
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| "invalid public key")?;
    let (ct, ss) = ek.encapsulate();
    Ok((ct.as_slice().to_vec(), ss.as_slice().to_vec()))
}

pub fn kem_decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if secret_key.len() != KEM_SECRET_KEY_SIZE {
        return Err("invalid ML-KEM-768 secret key length".into());
    }
    if ciphertext.len() != KEM_CIPHERTEXT_SIZE {
        return Err("invalid ML-KEM-768 ciphertext length".into());
    }
    let expanded = Array::<u8, _>::clone_from_slice(secret_key);
    let dk = DecapsulationKey::<MlKem768>::from_expanded_bytes(&expanded)
        .map_err(|_| "invalid secret key")?;
    let ss = dk
        .decapsulate_slice(ciphertext)
        .map_err(|_| "invalid ciphertext")?;
    Ok(ss.as_slice().to_vec())
}

pub fn needs_pq_rekey(hybrid: bool, session_started_at_ms: u64, messages_sent: u64) -> bool {
    if !hybrid {
        return false;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let age_exceeded = now.saturating_sub(session_started_at_ms) >= PQ_REKEY_MAX_AGE_MS;
    let count_exceeded = messages_sent >= PQ_REKEY_MAX_MESSAGES;
    age_exceeded || count_exceeded
}
