//! CBOR helpers matching Python `cbor2` encoding in the interop verifier.

use ciborium::value::Value;

/// Decode a CBOR blob into a `ciborium::value::Value` (map key order preserved).
pub fn decode_cbor(bytes: &[u8]) -> Result<Value, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(bytes)
}

/// Encode a `Value` to canonical CBOR bytes.
pub fn encode_cbor(value: &Value) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Lookup a text-keyed field in a CBOR map.
pub fn map_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    let entries = value.as_map()?;
    entries
        .iter()
        .find_map(|(k, v)| match k {
            Value::Text(s) if s == key => Some(v),
            _ => None,
        })
}

/// Extract a byte string field from a CBOR map.
pub fn map_bytes(value: &Value, key: &str) -> Option<Vec<u8>> {
    match map_field(value, key)? {
        Value::Bytes(bytes) => Some(bytes.clone()),
        _ => None,
    }
}

/// Unsigned invite CBOR: all map entries except `signature` and `pq_signature`.
pub fn invite_unsigned_cbor(bundle: &Value) -> Option<Vec<u8>> {
    let entries = bundle.as_map()?;
    let filtered: Vec<(Value, Value)> = entries
        .iter()
        .filter(|(k, _)| !is_signature_key(k))
        .cloned()
        .collect();
    encode_cbor(&Value::Map(filtered)).ok()
}

/// Unsigned delivery-profile CBOR with fixed field order (`interop_verifier._profile_unsigned`).
pub fn profile_unsigned_cbor(payload: &Value) -> Option<Vec<u8>> {
    const KEYS: &[&str] = &[
        "protocol",
        "version",
        "valid_from",
        "valid_until",
        "direct_hints",
        "relay_descriptors",
        "mailbox_params",
        "blob_classes",
        "receipt_policy",
    ];
    let entries = payload.as_map()?;
    let filtered: Vec<(Value, Value)> = KEYS
        .iter()
        .filter_map(|key| {
            entries.iter().find_map(|(k, v)| match k {
                Value::Text(s) if s == *key => Some((Value::Text((*key).to_string()), v.clone())),
                _ => None,
            })
        })
        .collect();
    encode_cbor(&Value::Map(filtered)).ok()
}

fn is_signature_key(key: &Value) -> bool {
    matches!(
        key,
        Value::Text(s) if s == "signature" || s == "pq_signature"
    )
}
