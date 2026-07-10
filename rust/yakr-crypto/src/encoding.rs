//! Shared encoding helpers matching the Python interop verifier.

use base64::{engine::general_purpose::URL_SAFE, Engine as _};

/// URL-safe base64 decode with padding, matching Python `_b64decode`.
pub fn base64url_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE.decode(padded)
}
