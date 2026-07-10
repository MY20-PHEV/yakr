use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;
use yakr_crypto::{derive_hybrid_master, hkdf_sha256};

use crate::hybrid_pq::{kem_decapsulate, kem_encapsulate};
use crate::identity::{contact_id_for, conversation_id_for, Identity, Contact};
use crate::invite::{invite_supports_hybrid, InviteBundle};
use crate::ratchet::RatchetState;

pub const PAIR_MASTER_INFO: &[u8] = b"yakr/v0.4/pair-master";

#[derive(Debug, Clone)]
pub struct PairingRequest {
    pub invite_secret: [u8; 32],
    pub joiner_name: String,
    pub joiner_signing_public: [u8; 32],
    pub joiner_agreement_public: [u8; 32],
    pub joiner_ephemeral_public: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PairingSecrets {
    pub ephemeral_private: [u8; 32],
    pub pq_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PairingResponse {
    pub inviter_ephemeral_public: [u8; 32],
    pub transcript_hash: [u8; 32],
}

pub fn build_pairing_request(
    identity: &Identity,
    invite: &InviteBundle,
    joiner_name: &str,
) -> Result<(PairingRequest, PairingSecrets), String> {
    let (ephemeral_private, ephemeral_public) = yakr_crypto::x25519_generate_keypair();
    let mut kem_ciphertext = Vec::new();
    let mut pq_secret = None;
    if invite_supports_hybrid(invite) {
        let (ct, ss) = kem_encapsulate(&invite.kem_public)?;
        kem_ciphertext = ct;
        pq_secret = Some(ss);
    }
    let request = PairingRequest {
        invite_secret: invite.invite_secret,
        joiner_name: joiner_name.to_string(),
        joiner_signing_public: identity.signing_public_bytes(),
        joiner_agreement_public: identity.agreement_public_bytes(),
        joiner_ephemeral_public: ephemeral_public,
        kem_ciphertext,
    };
    Ok((
        request,
        PairingSecrets {
            ephemeral_private,
            pq_secret,
        },
    ))
}

pub fn validate_pairing_request_for_invite(
    invite: &InviteBundle,
    request: &PairingRequest,
) -> Result<(), String> {
    if request.invite_secret != invite.invite_secret {
        return Err("pairing invite secret mismatch".into());
    }
    if invite_supports_hybrid(invite) {
        if request.kem_ciphertext.is_empty() {
            return Err("hybrid invite requires kem ciphertext".into());
        }
        return Ok(());
    }
    if !request.kem_ciphertext.is_empty() {
        return Err("unexpected kem ciphertext on classical invite".into());
    }
    Ok(())
}

pub fn pairing_transcript(
    invite: &InviteBundle,
    request: &PairingRequest,
    inviter_ephemeral_public: &[u8; 32],
) -> Result<[u8; 32], String> {
    validate_pairing_request_for_invite(invite, request)?;
    let mut parts: Vec<&[u8]> = vec![
        invite.protocol.as_bytes(),
        &invite.invite_secret,
        &invite.signing_public,
        &invite.agreement_public,
        &request.joiner_signing_public,
        &request.joiner_agreement_public,
        &request.joiner_ephemeral_public,
        inviter_ephemeral_public,
    ];
    if invite_supports_hybrid(invite) {
        parts.push(&request.kem_ciphertext);
    }
    let mut hasher = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hasher.update(b"|");
        }
        hasher.update(part);
    }
    Ok(hasher.finalize().into())
}

fn derive_pair_master(
    identity_shared: &[u8],
    ephemeral_shared: &[u8],
    transcript_hash: &[u8],
    pq_secret: Option<&[u8]>,
) -> [u8; 32] {
    if let Some(pq) = pq_secret {
        return derive_hybrid_master(identity_shared, ephemeral_shared, pq, transcript_hash);
    }
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(identity_shared);
    ikm.extend_from_slice(ephemeral_shared);
    hkdf_sha256(&ikm, PAIR_MASTER_INFO, transcript_hash)
}

pub fn inviter_complete_pairing(
    identity: &Identity,
    invite: &InviteBundle,
    request: &PairingRequest,
    inviter_ephemeral_private: [u8; 32],
) -> Result<(PairingResponse, Contact), String> {
    let inviter_ephemeral_public =
        x25519_dalek::PublicKey::from(&StaticSecret::from(inviter_ephemeral_private)).to_bytes();
    let transcript_hash = pairing_transcript(invite, request, &inviter_ephemeral_public)?;
    let mut hybrid = false;
    let pq_secret = if invite_supports_hybrid(invite) {
        if request.kem_ciphertext.is_empty() {
            return Err("hybrid invite requires kem ciphertext".into());
        }
        if identity.kem_private.is_empty() {
            return Err("inviter missing ML-KEM secret key".into());
        }
        hybrid = true;
        Some(kem_decapsulate(&identity.kem_private, &request.kem_ciphertext)?)
    } else {
        None
    };
    let identity_shared =
        yakr_crypto::x25519_shared_secret(&identity.agreement_private_bytes(), &request.joiner_agreement_public);
    let ephemeral_shared = yakr_crypto::x25519_shared_secret(
        &inviter_ephemeral_private,
        &request.joiner_ephemeral_public,
    );
    let master = derive_pair_master(
        &identity_shared,
        &ephemeral_shared,
        &transcript_hash,
        pq_secret.as_deref(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let contact = Contact {
        name: request.joiner_name.clone(),
        signing_public: request.joiner_signing_public,
        agreement_public: request.joiner_agreement_public,
        master_secret: master,
        conversation_id: conversation_id_for(&identity.name, &request.joiner_name),
        next_send_seq: 1,
        last_recv_seq: 0,
        contact_id: Some(contact_id_for(
            &request.joiner_signing_public,
            &request.joiner_agreement_public,
        )),
        transcript_hash: Some(transcript_hash),
        ratchet: Some(RatchetState::from_master(&master, true, hybrid)),
        hybrid_pq: hybrid,
        session_started_at: now,
        privacy_mode: crate::privacy::MODE_FAST.to_string(),
        mailbox_epoch_secs: 3600,
    };
    let response = PairingResponse {
        inviter_ephemeral_public,
        transcript_hash,
    };
    Ok((response, contact))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[derive(serde::Deserialize)]
    struct PairingTranscriptVector {
        name: String,
        invite_protocol: Option<String>,
        invite_secret_hex: String,
        invite_signing_public_hex: String,
        invite_agreement_public_hex: String,
        joiner_signing_public_hex: String,
        joiner_agreement_public_hex: String,
        joiner_ephemeral_public_hex: String,
        inviter_ephemeral_public_hex: String,
        inviter_agreement_private_hex: String,
        inviter_ephemeral_private_hex: String,
        joiner_agreement_private_hex: String,
        joiner_ephemeral_private_hex: String,
        expected_transcript_hash_hex: String,
        expected_identity_shared_hex: String,
        expected_ephemeral_shared_hex: String,
        expected_master_secret_hex: String,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    #[test]
    fn pairing_transcript_vectors() {
        let path = vectors_path("pairing_transcript.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vectors: Vec<PairingTranscriptVector> =
            serde_json::from_str(&raw).expect("parse pairing_transcript.json");

        for vector in vectors {
            let invite = crate::invite::InviteBundle {
                protocol: vector
                    .invite_protocol
                    .clone()
                    .unwrap_or_else(|| "yakr-v0.4".into()),
                inviter_name: "alice".into(),
                signing_public: hex::decode(&vector.invite_signing_public_hex).unwrap().try_into().unwrap(),
                agreement_public: hex::decode(&vector.invite_agreement_public_hex).unwrap().try_into().unwrap(),
                invite_secret: hex::decode(&vector.invite_secret_hex).unwrap().try_into().unwrap(),
                rendezvous_hint: "https://rendezvous.test/v1".into(),
                expires_at: 1_700_000_000_000,
                capabilities: vec!["direct_p2p".into()],
                signature: vec![0u8; 64],
                kem_public: Vec::new(),
            };
            let request = PairingRequest {
                invite_secret: invite.invite_secret,
                joiner_name: "bob".into(),
                joiner_signing_public: hex::decode(&vector.joiner_signing_public_hex).unwrap().try_into().unwrap(),
                joiner_agreement_public: hex::decode(&vector.joiner_agreement_public_hex).unwrap().try_into().unwrap(),
                joiner_ephemeral_public: hex::decode(&vector.joiner_ephemeral_public_hex).unwrap().try_into().unwrap(),
                kem_ciphertext: Vec::new(),
            };
            let inviter_ephemeral_public: [u8; 32] =
                hex::decode(&vector.inviter_ephemeral_public_hex).unwrap().try_into().unwrap();

            let transcript = pairing_transcript(&invite, &request, &inviter_ephemeral_public)
                .expect("pairing transcript");
            assert_eq!(
                hex::encode(transcript),
                vector.expected_transcript_hash_hex,
                "vector {}",
                vector.name
            );

            let inv_agree: [u8; 32] =
                hex::decode(&vector.inviter_agreement_private_hex).unwrap().try_into().unwrap();
            let inv_eph: [u8; 32] =
                hex::decode(&vector.inviter_ephemeral_private_hex).unwrap().try_into().unwrap();
            let join_agree_pub: [u8; 32] =
                hex::decode(&vector.joiner_agreement_public_hex).unwrap().try_into().unwrap();
            let join_eph_pub: [u8; 32] =
                hex::decode(&vector.joiner_ephemeral_public_hex).unwrap().try_into().unwrap();

            let identity_shared =
                yakr_crypto::x25519_shared_secret(&inv_agree, &join_agree_pub);
            let ephemeral_shared = yakr_crypto::x25519_shared_secret(&inv_eph, &join_eph_pub);
            assert_eq!(hex::encode(identity_shared), vector.expected_identity_shared_hex);
            assert_eq!(hex::encode(ephemeral_shared), vector.expected_ephemeral_shared_hex);

            let master = derive_pair_master(
                &identity_shared,
                &ephemeral_shared,
                &transcript,
                None,
            );
            assert_eq!(hex::encode(master), vector.expected_master_secret_hex);

            let join_agree: [u8; 32] =
                hex::decode(&vector.joiner_agreement_private_hex).unwrap().try_into().unwrap();
            let join_eph: [u8; 32] =
                hex::decode(&vector.joiner_ephemeral_private_hex).unwrap().try_into().unwrap();
            let joiner_master = derive_pair_master(
                &yakr_crypto::x25519_shared_secret(&join_agree, &invite.agreement_public),
                &yakr_crypto::x25519_shared_secret(&join_eph, &inviter_ephemeral_public),
                &transcript,
                None,
            );
            assert_eq!(master, joiner_master, "vector {} joiner master", vector.name);
        }
    }
}

pub fn joiner_complete_pairing(
    identity: &Identity,
    invite: &InviteBundle,
    request: &PairingRequest,
    secrets: &PairingSecrets,
    response: &PairingResponse,
) -> Result<Contact, String> {
    let expected = pairing_transcript(invite, request, &response.inviter_ephemeral_public)?;
    if expected != response.transcript_hash {
        return Err("pairing transcript mismatch".into());
    }
    let hybrid = invite_supports_hybrid(invite);
    let pq_secret: Option<Vec<u8>> = if hybrid {
        Some(
            secrets
                .pq_secret
                .clone()
                .ok_or("missing PQ shared secret for hybrid pairing".to_string())?,
        )
    } else {
        None
    };
    let identity_shared =
        yakr_crypto::x25519_shared_secret(&identity.agreement_private_bytes(), &invite.agreement_public);
    let ephemeral_shared = yakr_crypto::x25519_shared_secret(
        &secrets.ephemeral_private,
        &response.inviter_ephemeral_public,
    );
    let master = derive_pair_master(
        &identity_shared,
        &ephemeral_shared,
        &response.transcript_hash,
        pq_secret.as_deref(),
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Ok(Contact {
        name: invite.inviter_name.clone(),
        signing_public: invite.signing_public,
        agreement_public: invite.agreement_public,
        master_secret: master,
        conversation_id: conversation_id_for(&invite.inviter_name, &identity.name),
        next_send_seq: 1,
        last_recv_seq: 0,
        contact_id: Some(contact_id_for(&invite.signing_public, &invite.agreement_public)),
        transcript_hash: Some(response.transcript_hash),
        ratchet: Some(RatchetState::from_master(&master, false, hybrid)),
        hybrid_pq: hybrid,
        session_started_at: now,
        privacy_mode: crate::privacy::MODE_FAST.to_string(),
        mailbox_epoch_secs: 3600,
    })
}
