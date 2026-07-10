//! Hybrid post-quantum master secret derivation (`yakr-v0.6`).

use crate::hkdf::hkdf_sha256;

/// Domain separation for hybrid pairing master (`yakr-protocol-v1.md` §3.4).
pub const HYBRID_MASTER_INFO: &[u8] = b"yakr/v0.6/hybrid-master";

/// Combine classical X25519 shared secrets with an ML-KEM shared secret.
///
/// ```text
/// x_secret = identity_shared || ephemeral_shared
/// master   = HKDF-SHA256(ikm=x_secret||pq_secret, salt=transcript_hash, info=HYBRID_MASTER_INFO)
/// ```
pub fn derive_hybrid_master(
    identity_shared: &[u8],
    ephemeral_shared: &[u8],
    pq_secret: &[u8],
    transcript_hash: &[u8],
) -> [u8; 32] {
    let mut x_secret = Vec::with_capacity(identity_shared.len() + ephemeral_shared.len());
    x_secret.extend_from_slice(identity_shared);
    x_secret.extend_from_slice(ephemeral_shared);

    let mut ikm = Vec::with_capacity(x_secret.len() + pq_secret.len());
    ikm.extend_from_slice(&x_secret);
    ikm.extend_from_slice(pq_secret);

    hkdf_sha256(&ikm, HYBRID_MASTER_INFO, transcript_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct HybridKexVector {
        name: String,
        #[allow(dead_code)]
        description: String,
        identity_shared_hex: String,
        ephemeral_shared_hex: String,
        pq_secret_hex: String,
        transcript_hash_hex: String,
        expected_master_hex: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn hybrid_kex_vectors() {
        let path = vectors_path("hybrid_kex.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vectors: Vec<HybridKexVector> =
            serde_json::from_str(&raw).expect("parse hybrid_kex.json");

        assert!(!vectors.is_empty(), "hybrid_kex.json must contain vectors");

        for vector in vectors {
            let identity_shared = hex::decode(&vector.identity_shared_hex).expect("identity_shared");
            let ephemeral_shared =
                hex::decode(&vector.ephemeral_shared_hex).expect("ephemeral_shared");
            let pq_secret = hex::decode(&vector.pq_secret_hex).expect("pq_secret");
            let transcript_hash = hex::decode(&vector.transcript_hash_hex).expect("transcript_hash");
            let expected_master = hex::decode(&vector.expected_master_hex).expect("expected_master");

            assert_eq!(pq_secret.len(), 32, "{}: pq_secret must be 32 bytes", vector.name);

            let master = derive_hybrid_master(
                &identity_shared,
                &ephemeral_shared,
                &pq_secret,
                &transcript_hash,
            );

            assert_eq!(
                master.as_slice(),
                expected_master.as_slice(),
                "vector {} ({}) master mismatch",
                vector.name,
                vector.description
            );
        }
    }
}
