use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
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
    pub joiner_ratchet_public: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PairingSecrets {
    pub ephemeral_private: [u8; 32],
    pub ratchet_private: [u8; 32],
    pub pq_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct PairingResponse {
    pub inviter_ephemeral_public: [u8; 32],
    pub inviter_ratchet_public: [u8; 32],
    pub transcript_hash: [u8; 32],
}

fn ratchet_public(private: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

pub fn build_pairing_request(
    identity: &Identity,
    invite: &InviteBundle,
    joiner_name: &str,
) -> Result<(PairingRequest, PairingSecrets), String> {
    let (ephemeral_private, ephemeral_public) = yakr_crypto::x25519_generate_keypair();
    let (ratchet_private, ratchet_public) = yakr_crypto::x25519_generate_keypair();
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
        joiner_ratchet_public: ratchet_public,
        kem_ciphertext,
    };
    Ok((
        request,
        PairingSecrets {
            ephemeral_private,
            ratchet_private,
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
    if request.joiner_ratchet_public.len() != 32 {
        return Err("pairing request missing joiner ratchet public key".into());
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
    inviter_ratchet_public: &[u8; 32],
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
        &request.joiner_ratchet_public,
        inviter_ratchet_public,
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
    inviter_ratchet_private: Option<[u8; 32]>,
) -> Result<(PairingResponse, Contact), String> {
    let inviter_ephemeral_public = ratchet_public(&inviter_ephemeral_private);
    let inviter_ratchet_private = inviter_ratchet_private.unwrap_or_else(|| {
        let (private, _) = yakr_crypto::x25519_generate_keypair();
        private
    });
    let inviter_ratchet_public = ratchet_public(&inviter_ratchet_private);
    let transcript_hash = pairing_transcript(
        invite,
        request,
        &inviter_ephemeral_public,
        &inviter_ratchet_public,
    )?;
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
    let mut ratchet = RatchetState::from_master(&master, true, hybrid, Some(inviter_ratchet_private));
    ratchet.pending_pairing_dh_ratchet_peer = Some(request.joiner_ratchet_public);
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
        ratchet: Some(ratchet),
        hybrid_pq: hybrid,
        session_started_at: now,
        privacy_mode: crate::privacy::MODE_FAST.to_string(),
        mailbox_epoch_secs: 3600,
    };
    let response = PairingResponse {
        inviter_ephemeral_public,
        inviter_ratchet_public,
        transcript_hash,
    };
    Ok((response, contact))
}

pub fn pairing_request_to_bytes(request: &PairingRequest) -> Result<Vec<u8>, String> {
    use ciborium::value::Value;
    let mut entries = vec![
        (
            Value::Text("invite_secret".into()),
            Value::Bytes(request.invite_secret.to_vec()),
        ),
        (
            Value::Text("joiner_name".into()),
            Value::Text(request.joiner_name.clone()),
        ),
        (
            Value::Text("joiner_signing_public".into()),
            Value::Bytes(request.joiner_signing_public.to_vec()),
        ),
        (
            Value::Text("joiner_agreement_public".into()),
            Value::Bytes(request.joiner_agreement_public.to_vec()),
        ),
        (
            Value::Text("joiner_ephemeral_public".into()),
            Value::Bytes(request.joiner_ephemeral_public.to_vec()),
        ),
        (
            Value::Text("joiner_ratchet_public".into()),
            Value::Bytes(request.joiner_ratchet_public.to_vec()),
        ),
        (
            Value::Text("joiner_profile".into()),
            Value::Bytes(Vec::new()),
        ),
    ];
    if !request.kem_ciphertext.is_empty() {
        entries.push((
            Value::Text("kem_ciphertext".into()),
            Value::Bytes(request.kem_ciphertext.clone()),
        ));
    }
    yakr_crypto::cbor::encode_cbor(&Value::Map(entries)).map_err(|e| format!("{e:?}"))
}

pub fn pairing_request_from_bytes(data: &[u8]) -> Result<PairingRequest, String> {
    let value = yakr_crypto::cbor::decode_cbor(data).map_err(|e| format!("{e:?}"))?;
    let get_bytes = |key: &str| -> Result<Vec<u8>, String> {
        yakr_crypto::cbor::map_bytes(&value, key).ok_or_else(|| format!("missing {key}"))
    };
    let joiner_name = match yakr_crypto::cbor::map_field(&value, "joiner_name") {
        Some(ciborium::value::Value::Text(s)) => s.clone(),
        _ => return Err("missing joiner_name".into()),
    };
    Ok(PairingRequest {
        invite_secret: get_bytes("invite_secret")?
            .try_into()
            .map_err(|_| "invite_secret".to_string())?,
        joiner_name,
        joiner_signing_public: get_bytes("joiner_signing_public")?
            .try_into()
            .map_err(|_| "joiner_signing_public".to_string())?,
        joiner_agreement_public: get_bytes("joiner_agreement_public")?
            .try_into()
            .map_err(|_| "joiner_agreement_public".to_string())?,
        joiner_ephemeral_public: get_bytes("joiner_ephemeral_public")?
            .try_into()
            .map_err(|_| "joiner_ephemeral_public".to_string())?,
        joiner_ratchet_public: yakr_crypto::cbor::map_bytes(&value, "joiner_ratchet_public")
            .unwrap_or_default()
            .try_into()
            .map_err(|_| "joiner_ratchet_public".to_string())?,
        kem_ciphertext: yakr_crypto::cbor::map_bytes(&value, "kem_ciphertext").unwrap_or_default(),
    })
}

pub fn pairing_response_to_bytes(response: &PairingResponse) -> Result<Vec<u8>, String> {
    use ciborium::value::Value;
    let entries = vec![
        (
            Value::Text("inviter_ephemeral_public".into()),
            Value::Bytes(response.inviter_ephemeral_public.to_vec()),
        ),
        (
            Value::Text("inviter_ratchet_public".into()),
            Value::Bytes(response.inviter_ratchet_public.to_vec()),
        ),
        (
            Value::Text("transcript_hash".into()),
            Value::Bytes(response.transcript_hash.to_vec()),
        ),
        (
            Value::Text("inviter_profile".into()),
            Value::Bytes(Vec::new()),
        ),
    ];
    yakr_crypto::cbor::encode_cbor(&Value::Map(entries)).map_err(|e| format!("{e:?}"))
}

pub fn pairing_response_from_bytes(data: &[u8]) -> Result<PairingResponse, String> {
    let value = yakr_crypto::cbor::decode_cbor(data).map_err(|e| format!("{e:?}"))?;
    let get_bytes = |key: &str| -> Result<Vec<u8>, String> {
        yakr_crypto::cbor::map_bytes(&value, key).ok_or_else(|| format!("missing {key}"))
    };
    Ok(PairingResponse {
        inviter_ephemeral_public: get_bytes("inviter_ephemeral_public")?
            .try_into()
            .map_err(|_| "inviter_ephemeral_public".to_string())?,
        inviter_ratchet_public: yakr_crypto::cbor::map_bytes(&value, "inviter_ratchet_public")
            .unwrap_or_default()
            .try_into()
            .map_err(|_| "inviter_ratchet_public".to_string())?,
        transcript_hash: get_bytes("transcript_hash")?
            .try_into()
            .map_err(|_| "transcript_hash".to_string())?,
    })
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct PairingSecretsFile {
    pub ephemeral_private_hex: String,
    pub ratchet_private_hex: String,
    #[serde(default)]
    pub pq_secret_hex: Option<String>,
}

impl PairingSecretsFile {
    pub fn from_secrets(secrets: &PairingSecrets) -> Self {
        Self {
            ephemeral_private_hex: hex::encode(secrets.ephemeral_private),
            ratchet_private_hex: hex::encode(secrets.ratchet_private),
            pq_secret_hex: secrets.pq_secret.as_ref().map(hex::encode),
        }
    }

    pub fn to_secrets(&self) -> Result<PairingSecrets, String> {
        let ephemeral_private: [u8; 32] = hex::decode(&self.ephemeral_private_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "ephemeral_private".to_string())?;
        let ratchet_private: [u8; 32] = hex::decode(&self.ratchet_private_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "ratchet_private".to_string())?;
        let pq_secret = match &self.pq_secret_hex {
            Some(hex_value) => Some(hex::decode(hex_value).map_err(|e| e.to_string())?),
            None => None,
        };
        Ok(PairingSecrets {
            ephemeral_private,
            ratchet_private,
            pq_secret,
        })
    }
}

pub fn joiner_complete_pairing(
    identity: &Identity,
    invite: &InviteBundle,
    request: &PairingRequest,
    secrets: &PairingSecrets,
    response: &PairingResponse,
) -> Result<Contact, String> {
    if response.inviter_ratchet_public.len() != 32 {
        return Err("pairing response missing inviter ratchet public key".into());
    }
    let expected = pairing_transcript(
        invite,
        request,
        &response.inviter_ephemeral_public,
        &response.inviter_ratchet_public,
    )?;
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
    let mut ratchet = RatchetState::from_master(&master, false, hybrid, Some(secrets.ratchet_private));
    ratchet.pairing_recv_init(response.inviter_ratchet_public)?;
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
        ratchet: Some(ratchet),
        hybrid_pq: hybrid,
        session_started_at: now,
        privacy_mode: crate::privacy::MODE_FAST.to_string(),
        mailbox_epoch_secs: 3600,
    })
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
        joiner_ratchet_public_hex: String,
        inviter_ephemeral_public_hex: String,
        inviter_ratchet_public_hex: String,
        inviter_agreement_private_hex: String,
        inviter_ephemeral_private_hex: String,
        joiner_agreement_private_hex: String,
        joiner_ephemeral_private_hex: String,
        expected_transcript_hash_hex: String,
        expected_identity_shared_hex: String,
        expected_ephemeral_shared_hex: String,
        expected_master_secret_hex: String,
        invite_kem_public_hex: Option<String>,
        kem_ciphertext_hex: Option<String>,
        inviter_kem_secret_hex: Option<String>,
        expected_pq_secret_hex: Option<String>,
    }

    fn vectors_path(file: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/spec/test-vectors-v1")
            .join(file)
    }

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    #[test]
    fn pairing_transcript_vectors() {
        let path = vectors_path("pairing_transcript.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let vectors: Vec<PairingTranscriptVector> =
            serde_json::from_str(&raw).expect("parse pairing_transcript.json");

        for vector in vectors {
            let hybrid = vector.kem_ciphertext_hex.is_some();
            let mut capabilities = vec!["direct_p2p".to_string()];
            if hybrid {
                capabilities.push(crate::hybrid_pq::HYBRID_PQ_CAPABILITY.to_string());
            }
            let invite = crate::invite::InviteBundle {
                protocol: vector
                    .invite_protocol
                    .clone()
                    .unwrap_or_else(|| "yakr-v0.4".into()),
                inviter_name: "alice".into(),
                signing_public: hex32(&vector.invite_signing_public_hex),
                agreement_public: hex32(&vector.invite_agreement_public_hex),
                invite_secret: hex32(&vector.invite_secret_hex),
                rendezvous_hint: "https://rendezvous.test/v1".into(),
                expires_at: 1_700_000_000_000,
                capabilities,
                signature: vec![0u8; 64],
                kem_public: vector
                    .invite_kem_public_hex
                    .as_ref()
                    .map(|h| hex::decode(h).unwrap())
                    .unwrap_or_default(),
            };
            let request = PairingRequest {
                invite_secret: invite.invite_secret,
                joiner_name: "bob".into(),
                joiner_signing_public: hex32(&vector.joiner_signing_public_hex),
                joiner_agreement_public: hex32(&vector.joiner_agreement_public_hex),
                joiner_ephemeral_public: hex32(&vector.joiner_ephemeral_public_hex),
                joiner_ratchet_public: hex32(&vector.joiner_ratchet_public_hex),
                kem_ciphertext: vector
                    .kem_ciphertext_hex
                    .as_ref()
                    .map(|h| hex::decode(h).unwrap())
                    .unwrap_or_default(),
            };
            let inviter_ephemeral_public = hex32(&vector.inviter_ephemeral_public_hex);
            let inviter_ratchet_public = hex32(&vector.inviter_ratchet_public_hex);

            let transcript = pairing_transcript(
                &invite,
                &request,
                &inviter_ephemeral_public,
                &inviter_ratchet_public,
            )
            .expect("pairing transcript");
            assert_eq!(
                hex::encode(transcript),
                vector.expected_transcript_hash_hex,
                "vector {}",
                vector.name
            );

            let inv_agree = hex32(&vector.inviter_agreement_private_hex);
            let inv_eph = hex32(&vector.inviter_ephemeral_private_hex);
            let join_agree_pub = hex32(&vector.joiner_agreement_public_hex);
            let join_eph_pub = hex32(&vector.joiner_ephemeral_public_hex);

            let identity_shared = yakr_crypto::x25519_shared_secret(&inv_agree, &join_agree_pub);
            let ephemeral_shared = yakr_crypto::x25519_shared_secret(&inv_eph, &join_eph_pub);
            assert_eq!(hex::encode(identity_shared), vector.expected_identity_shared_hex);
            assert_eq!(hex::encode(ephemeral_shared), vector.expected_ephemeral_shared_hex);

            let pq_secret = if hybrid {
                let kem_secret = vector.inviter_kem_secret_hex.as_ref().unwrap();
                let kem_ct = vector.kem_ciphertext_hex.as_ref().unwrap();
                let ss = kem_decapsulate(
                    &hex::decode(kem_secret).unwrap(),
                    &hex::decode(kem_ct).unwrap(),
                )
                .expect("kem decapsulate");
                assert_eq!(
                    hex::encode(&ss),
                    vector.expected_pq_secret_hex.as_ref().unwrap().as_str()
                );
                Some(ss)
            } else {
                None
            };

            let master = derive_pair_master(
                &identity_shared,
                &ephemeral_shared,
                &transcript,
                pq_secret.as_deref(),
            );
            assert_eq!(hex::encode(master), vector.expected_master_secret_hex);

            let join_agree = hex32(&vector.joiner_agreement_private_hex);
            let join_eph = hex32(&vector.joiner_ephemeral_private_hex);
            let joiner_master = derive_pair_master(
                &yakr_crypto::x25519_shared_secret(&join_agree, &invite.agreement_public),
                &yakr_crypto::x25519_shared_secret(&join_eph, &inviter_ephemeral_public),
                &transcript,
                pq_secret.as_deref(),
            );
            assert_eq!(master, joiner_master, "vector {} joiner master", vector.name);
        }
    }

    #[test]
    fn pairing_path_rotates_dh_epoch() {
        use crate::invite::create_invite;
        use crate::session::Session;

        let alice = Identity::generate("alice", false);
        let bob = Identity::generate("bob", false);
        let invite = create_invite(&alice, "http://test", 60_000, false).unwrap();
        let (request, secrets) = build_pairing_request(&bob, &invite, "bob").unwrap();
        let (inviter_ephemeral, _) = yakr_crypto::x25519_generate_keypair();
        let (response, mut alice_contact) =
            inviter_complete_pairing(&alice, &invite, &request, inviter_ephemeral, None).unwrap();
        let mut bob_contact =
            joiner_complete_pairing(&bob, &invite, &request, &secrets, &response).unwrap();

        let alice_ratchet = alice_contact.ratchet.as_mut().unwrap();
        let bob_ratchet = bob_contact.ratchet.as_mut().unwrap();
        assert_eq!(request.joiner_ratchet_public, bob_ratchet.dh_self_public);
        assert_eq!(response.inviter_ratchet_public, alice_ratchet.dh_self_public);
        assert!(alice_ratchet.dh_peer_public.is_none());
        assert_eq!(
            bob_ratchet.dh_peer_public,
            Some(response.inviter_ratchet_public)
        );

        let alice_root = alice_ratchet.root_key;
        let bob_root = bob_ratchet.root_key;
        let mut alice_session = Session::new(alice, alice_contact).unwrap();
        let mut bob_session = Session::new(bob, bob_contact).unwrap();
        bob_session
            .decrypt_outer(&alice_session.encrypt_text("one").unwrap().outer_blob)
            .unwrap();
        alice_session
            .decrypt_outer(&bob_session.encrypt_text("two").unwrap().outer_blob)
            .unwrap();
        assert_ne!(alice_session.contact.ratchet.as_ref().unwrap().root_key, alice_root);
        assert_ne!(bob_session.contact.ratchet.as_ref().unwrap().root_key, bob_root);
    }
}
