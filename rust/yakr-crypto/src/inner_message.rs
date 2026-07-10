//! Inner message canonical JSON (`yakr-protocol-v1.md` §4.1).

use serde_json::Value;

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
}
