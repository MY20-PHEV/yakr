use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterBlob {
    pub version: u32,
    pub mailbox_tag: [u8; 32],
    pub expires_at: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct RelayBlobJson {
    pub mailbox_tag: String,
    pub expires_at: u64,
    pub ciphertext: String,
}

pub fn b64encode(data: &[u8]) -> String {
    URL_SAFE.encode(data).trim_end_matches('=').to_string()
}

pub fn b64decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE.decode(padded)
}

impl OuterBlob {
    pub fn to_relay_json(&self) -> RelayBlobJson {
        RelayBlobJson {
            mailbox_tag: b64encode(&self.mailbox_tag),
            expires_at: self.expires_at,
            ciphertext: b64encode(&self.ciphertext),
        }
    }

    pub fn from_relay_json(payload: &RelayBlobJson) -> Result<Self, String> {
        let tag = b64decode(&payload.mailbox_tag).map_err(|e| e.to_string())?;
        let ciphertext = b64decode(&payload.ciphertext).map_err(|e| e.to_string())?;
        Ok(Self {
            version: 1,
            mailbox_tag: tag.try_into().map_err(|_| "mailbox_tag must be 32 bytes")?,
            expires_at: payload.expires_at,
            ciphertext,
        })
    }
}

pub use yakr_crypto::{message_id, InnerMessage, MessageType};
