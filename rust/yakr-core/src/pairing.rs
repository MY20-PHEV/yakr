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

pub fn pairing_transcript(
    invite: &InviteBundle,
    request: &PairingRequest,
    inviter_ephemeral_public: &[u8; 32],
) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = vec![
        &invite.invite_secret,
        &invite.signing_public,
        &invite.agreement_public,
        &request.joiner_signing_public,
        &request.joiner_agreement_public,
        &request.joiner_ephemeral_public,
        inviter_ephemeral_public,
    ];
    if !request.kem_ciphertext.is_empty() {
        parts.push(&request.kem_ciphertext);
    }
    let mut hasher = Sha256::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            hasher.update(b"|");
        }
        hasher.update(part);
    }
    hasher.finalize().into()
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
    let transcript_hash = pairing_transcript(invite, request, &inviter_ephemeral_public);
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

pub fn joiner_complete_pairing(
    identity: &Identity,
    invite: &InviteBundle,
    request: &PairingRequest,
    secrets: &PairingSecrets,
    response: &PairingResponse,
) -> Result<Contact, String> {
    let expected = pairing_transcript(invite, request, &response.inviter_ephemeral_public);
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
