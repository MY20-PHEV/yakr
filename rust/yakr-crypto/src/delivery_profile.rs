//! Delivery profile verification (`yakr-protocol-v1.md` §5.2).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::cbor::{decode_cbor, map_bytes, profile_unsigned_cbor};
use crate::encoding::base64url_decode;

/// Verify a signed delivery profile CBOR blob.
pub fn verify_delivery_profile(
    profile_b64: &str,
    expected_signing_public_hex: &str,
    expected_version: u64,
) -> bool {
    let Ok(raw) = base64url_decode(profile_b64) else {
        return false;
    };
    let Ok(payload) = decode_cbor(&raw) else {
        return false;
    };

    let signing_public = match hex::decode(expected_signing_public_hex) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let Ok(signing_key) = signing_public.as_slice().try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(signing_key) else {
        return false;
    };

    let Some(signature_bytes) = map_bytes(&payload, "signature") else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };

    let Some(unsigned) = profile_unsigned_cbor(&payload) else {
        return false;
    };
    if verifying_key.verify(&unsigned, &signature).is_err() {
        return false;
    }

    match crate::cbor::map_field(&payload, "version") {
        Some(ciborium::value::Value::Integer(v)) => i128::from(*v) == expected_version as i128,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct DeliveryProfileVector {
        name: String,
        profile_b64: String,
        signing_public_hex: String,
        version: u64,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn delivery_profile_vector() {
        let path = vectors_path("delivery_profile.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vector: DeliveryProfileVector =
            serde_json::from_str(&raw).expect("parse delivery_profile.json");

        assert!(
            verify_delivery_profile(
                &vector.profile_b64,
                &vector.signing_public_hex,
                vector.version,
            ),
            "vector {} failed",
            vector.name
        );
    }

    #[test]
    fn profile_unsigned_cbor_matches_python() {
        const EXPECTED_UNSIGNED_HEX: &str = "a96870726f746f636f6c6979616b722d76302e356776657273696f6e016a76616c69645f66726f6d1b0000019f3cdd6ed56b76616c69645f756e74696c1b0000019f60e9f2d56c6469726563745f68696e7473817368747470733a2f2f6469726563742e746573747172656c61795f64657363726970746f727381a4646e616d656572656c617964726f6c6564626f74686375726c7268747470733a2f2f72656c61792e746573746b777261705f73656372657458201ac8ee7efe5990ca5bdecc03200527386cefc912bf88bbe9211d6e94166e3c686e6d61696c626f785f706172616d73a26a65706f63685f73656373190e106e646972656374696f6e5f73616c74406c626c6f625f636c6173736573811910006e726563656970745f706f6c696379676d696e696d616c";

        let path = vectors_path("delivery_profile.json");
        let vector: DeliveryProfileVector =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let payload = decode_cbor(&base64url_decode(&vector.profile_b64).unwrap()).unwrap();
        let unsigned = profile_unsigned_cbor(&payload).unwrap();
        assert_eq!(hex::encode(unsigned), EXPECTED_UNSIGNED_HEX);
    }
}
