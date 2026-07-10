//! Inner message canonical JSON (`yakr-protocol-v1.md` §4.1).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Inner cleartext message types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageType {
    Text,
    Receipt,
    Profile,
    Presence,
}

/// Full inner message matching Python `InnerMessage`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InnerMessage {
    pub version: u32,
    pub conversation_id: String,
    pub sender_device_id: String,
    pub seq: u64,
    pub created_at: u64,
    pub valid_until: u64,
    #[serde(rename = "type")]
    pub message_type: MessageType,
    pub body: Option<String>,
    pub message_id: Option<String>,
}

impl InnerMessage {
    pub fn text(
        conversation_id: impl Into<String>,
        sender_device_id: impl Into<String>,
        seq: u64,
        body: impl Into<String>,
        created_at: u64,
        valid_until: u64,
    ) -> Self {
        Self {
            version: 1,
            conversation_id: conversation_id.into(),
            sender_device_id: sender_device_id.into(),
            seq,
            created_at,
            valid_until,
            message_type: MessageType::Text,
            body: Some(body.into()),
            message_id: None,
        }
    }

    /// Canonical compact sorted JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let value = serde_json::to_value(self)?;
        serde_json::to_vec(&value)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

/// Message id from outer ciphertext (`yakr/v0.1/message-id`).
pub fn message_id(ciphertext: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"yakr/v0.1/message-id|");
    hasher.update(ciphertext);
    hex::encode(hasher.finalize())
}

/// Parsed fields checked by `inner_message.json` interop vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerMessageFields {
    pub conversation_id: String,
    pub seq: u64,
    pub body: String,
}

#[derive(Debug)]
pub enum InnerMessageError {
    InvalidJson(serde_json::Error),
    MissingField(&'static str),
    WrongType(&'static str),
    NotCanonical,
}

impl std::fmt::Display for InnerMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(e) => write!(f, "invalid JSON: {e}"),
            Self::MissingField(field) => write!(f, "missing field: {field}"),
            Self::WrongType(field) => write!(f, "wrong type for field: {field}"),
            Self::NotCanonical => write!(f, "JSON is not canonical sorted compact form"),
        }
    }
}

impl std::error::Error for InnerMessageError {}

/// Parse and verify canonical inner-message JSON bytes.
///
/// Canonical form matches Python `json.dumps(..., separators=(",", ":"), sort_keys=True)`.
pub fn verify_inner_message_json(json_raw: &[u8]) -> Result<InnerMessageFields, InnerMessageError> {
    let payload: Value =
        serde_json::from_slice(json_raw).map_err(InnerMessageError::InvalidJson)?;

    let conversation_id = payload
        .get("conversation_id")
        .and_then(Value::as_str)
        .ok_or(InnerMessageError::MissingField("conversation_id"))?
        .to_string();

    let seq = payload
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(InnerMessageError::WrongType("seq"))?;

    let body = payload
        .get("body")
        .and_then(Value::as_str)
        .ok_or(InnerMessageError::MissingField("body"))?
        .to_string();

    let canonical =
        serde_json::to_vec(&payload).map_err(InnerMessageError::InvalidJson)?;
    if canonical != json_raw {
        return Err(InnerMessageError::NotCanonical);
    }

    Ok(InnerMessageFields {
        conversation_id,
        seq,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct InnerMessageVector {
        name: String,
        json: String,
        conversation_id: String,
        seq: u64,
        body: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn inner_message_vector() {
        let path = vectors_path("inner_message.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vector: InnerMessageVector =
            serde_json::from_str(&raw).expect("parse inner_message.json");

        let json_raw = vector.json.as_bytes();
        let parsed = verify_inner_message_json(json_raw)
            .unwrap_or_else(|e| panic!("vector {} failed: {e}", vector.name));

        assert_eq!(parsed.conversation_id, vector.conversation_id);
        assert_eq!(parsed.seq, vector.seq);
        assert_eq!(parsed.body, vector.body);
    }

    #[test]
    fn inner_message_round_trip_encrypt() {
        use crate::aead::{xchacha_decrypt, xchacha_encrypt};
        use crate::master::derive_message_key;

        let inner = InnerMessage::text(
            "pairwise_alice_bob",
            "abc123",
            1,
            "hello rust",
            1_700_000_000_000,
            1_700_086_400_000,
        );
        let raw = inner.to_bytes().unwrap();
        verify_inner_message_json(&raw).unwrap();

        let master = [7u8; 32];
        let key = derive_message_key(&master, 1);
        let ciphertext = xchacha_encrypt(&key, &raw, b"").unwrap();
        let plain = xchacha_decrypt(&key, &ciphertext, b"").unwrap();
        assert_eq!(plain, raw);
        let decoded = InnerMessage::from_bytes(&plain).unwrap();
        assert_eq!(decoded.body.as_deref(), Some("hello rust"));
    }
}
