//! Outer blob relay JSON (`yakr-protocol-v1.md` §4.2).

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterBlobFields {
    pub version: u32,
    pub mailbox_tag: [u8; 32],
    pub expires_at: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum OuterBlobError {
    MissingField(&'static str),
    InvalidBase64(base64::DecodeError),
    InvalidTagLength,
}

impl std::fmt::Display for OuterBlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing field: {field}"),
            Self::InvalidBase64(e) => write!(f, "invalid base64: {e}"),
            Self::InvalidTagLength => write!(f, "mailbox_tag must be 32 bytes"),
        }
    }
}

impl std::error::Error for OuterBlobError {}

#[derive(Deserialize)]
struct RelayBlobJson {
    mailbox_tag: String,
    expires_at: u64,
    ciphertext: String,
}

fn b64decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE.decode(padded)
}

/// Decode relay POST JSON and validate mailbox tag length.
pub fn verify_outer_blob_relay_json(
    relay: &serde_json::Value,
) -> Result<OuterBlobFields, OuterBlobError> {
    let payload: RelayBlobJson = serde_json::from_value(relay.clone())
        .map_err(|_| OuterBlobError::MissingField("relay_json"))?;
    let tag = b64decode(&payload.mailbox_tag).map_err(OuterBlobError::InvalidBase64)?;
    let ciphertext = b64decode(&payload.ciphertext).map_err(OuterBlobError::InvalidBase64)?;
    let mailbox_tag: [u8; 32] = tag
        .try_into()
        .map_err(|_| OuterBlobError::InvalidTagLength)?;
    Ok(OuterBlobFields {
        version: 1,
        mailbox_tag,
        expires_at: payload.expires_at,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct OuterBlobVector {
        name: String,
        version: u32,
        relay_json: serde_json::Value,
        mailbox_tag_hex: String,
        expires_at: u64,
        ciphertext_hex: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn outer_blob_vector() {
        let path = vectors_path("outer_blob.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vector: OuterBlobVector =
            serde_json::from_str(&raw).expect("parse outer_blob.json");

        let parsed = verify_outer_blob_relay_json(&vector.relay_json)
            .unwrap_or_else(|e| panic!("vector {} failed: {e}", vector.name));

        assert_eq!(parsed.version, vector.version);
        assert_eq!(hex::encode(parsed.mailbox_tag), vector.mailbox_tag_hex);
        assert_eq!(parsed.expires_at, vector.expires_at);
        assert_eq!(hex::encode(parsed.ciphertext), vector.ciphertext_hex);
    }
}
