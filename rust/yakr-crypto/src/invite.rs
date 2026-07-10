//! Invite bundle verification (`yakr-protocol-v1.md` §5.1).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::cbor::{decode_cbor, invite_unsigned_cbor, map_bytes};
use crate::encoding::base64url_decode;

/// Verify a classical invite bundle and its safety code.
pub fn verify_invite_bundle(
    bundle_b64: &str,
    expected_signing_public_hex: &str,
    expected_safety_code: &str,
) -> bool {
    let Ok(raw) = base64url_decode(bundle_b64) else {
        return false;
    };
    let Ok(bundle) = decode_cbor(&raw) else {
        return false;
    };

    let Some(signing_public) = map_bytes(&bundle, "signing_public") else {
        return false;
    };
    if hex::encode(&signing_public) != expected_signing_public_hex {
        return false;
    }

    let Some(agreement_public) = map_bytes(&bundle, "agreement_public") else {
        return false;
    };
    let Some(signature_bytes) = map_bytes(&bundle, "signature") else {
        return false;
    };

    let Some(unsigned) = invite_unsigned_cbor(&bundle) else {
        return false;
    };

    let Ok(signing_key) = signing_public.as_slice().try_into() else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(signing_key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature_bytes) else {
        return false;
    };
    if verifying_key.verify(&unsigned, &signature).is_err() {
        return false;
    }

    derive_safety_code(&signing_public, &agreement_public) == expected_safety_code
}

/// Safety code from signing + agreement public keys (§5.1).
pub fn derive_safety_code(signing_public: &[u8], agreement_public: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(signing_public);
    hasher.update(agreement_public);
    let digest = hasher.finalize();
    let digits: String = digest[..10]
        .iter()
        .map(|byte| (byte % 10).to_string())
        .collect();
    format!(
        "{} {} {}",
        &digits[0..4],
        &digits[4..8],
        &digits[8..10]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct InviteVector {
        name: String,
        bundle_b64: String,
        signing_public_hex: String,
        safety_code: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn invite_vector() {
        let path = vectors_path("invite.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vector: InviteVector = serde_json::from_str(&raw).expect("parse invite.json");

        assert!(
            verify_invite_bundle(
                &vector.bundle_b64,
                &vector.signing_public_hex,
                &vector.safety_code,
            ),
            "vector {} failed",
            vector.name
        );
    }

    #[test]
    fn invite_unsigned_cbor_matches_python() {
        const EXPECTED_UNSIGNED_HEX: &str = "a86870726f746f636f6c6979616b722d76302e346c696e76697465725f6e616d656c766563746f722d616c6963656e7369676e696e675f7075626c6963582003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b87061677265656d656e745f7075626c69635820358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd1662546d696e766974655f73656372657458207c80f29f102b124447807a75300bf08a82139f7979cca772422519648daa2e626f72656e64657a766f75735f68696e74781a68747470733a2f2f72656e64657a766f75732e746573742f76316a657870697265735f61741b0000019f4203cad46c6361706162696c6974696573836a6469726563745f7032706c667269656e645f72656c61796d73746f72655f666f7277617264";

        let path = vectors_path("invite.json");
        let vector: InviteVector =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let bundle = decode_cbor(&base64url_decode(&vector.bundle_b64).unwrap()).unwrap();
        let unsigned = invite_unsigned_cbor(&bundle).unwrap();
        assert_eq!(hex::encode(unsigned), EXPECTED_UNSIGNED_HEX);
    }
}
