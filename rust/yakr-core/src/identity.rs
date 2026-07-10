use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;
use yakr_crypto::{derive_master_secret, x25519_shared_secret};

use crate::hybrid_pq::kem_generate_keypair;
use crate::message::{b64decode, b64encode};
use crate::ratchet::RatchetState;

#[derive(Clone)]
pub struct Identity {
    pub name: String,
    signing_private: SigningKey,
    agreement_private: StaticSecret,
    pub kem_public: Vec<u8>,
    pub kem_private: Vec<u8>,
}

impl Identity {
    pub fn generate(name: impl Into<String>, hybrid_pq: bool) -> Self {
        let mut secret = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut secret);
        let signing_private = SigningKey::from_bytes(&secret);
        let agreement_private = StaticSecret::random_from_rng(OsRng);
        let (kem_public, kem_private) = if hybrid_pq {
            kem_generate_keypair()
        } else {
            (Vec::new(), Vec::new())
        };
        Self {
            name: name.into(),
            signing_private,
            agreement_private,
            kem_public,
            kem_private,
        }
    }

    pub fn device_id(&self) -> String {
        hex::encode(self.signing_public_bytes())[..16].to_string()
    }

    pub fn signing_public_bytes(&self) -> [u8; 32] {
        self.signing_private.verifying_key().to_bytes()
    }

    pub fn agreement_public_bytes(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.agreement_private).to_bytes()
    }

    pub fn agreement_private_bytes(&self) -> [u8; 32] {
        self.agreement_private.to_bytes()
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_private
    }

    pub fn agreement_secret(&self) -> &StaticSecret {
        &self.agreement_private
    }

    pub fn to_dict(&self) -> IdentityDict {
        let mut dict = IdentityDict {
            name: self.name.clone(),
            signing_private: b64encode(self.signing_private.to_bytes().as_slice()),
            agreement_private: b64encode(&self.agreement_private.to_bytes()),
            kem_public: None,
            kem_private: None,
        };
        if !self.kem_private.is_empty() {
            dict.kem_public = Some(b64encode(&self.kem_public));
            dict.kem_private = Some(b64encode(&self.kem_private));
        }
        dict
    }

    pub fn from_dict(dict: &IdentityDict) -> Result<Self, String> {
        let signing_bytes: [u8; 32] = b64decode(&dict.signing_private)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signing_private")?;
        let agreement_bytes: [u8; 32] = b64decode(&dict.agreement_private)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "agreement_private")?;
        Ok(Self {
            name: dict.name.clone(),
            signing_private: SigningKey::from_bytes(&signing_bytes),
            agreement_private: StaticSecret::from(agreement_bytes),
            kem_public: dict
                .kem_public
                .as_ref()
                .map(|v| b64decode(v).unwrap_or_default())
                .unwrap_or_default(),
            kem_private: dict
                .kem_private
                .as_ref()
                .map(|v| b64decode(v).unwrap_or_default())
                .unwrap_or_default(),
        })
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.to_dict()).unwrap();
        std::fs::write(path, json)
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let dict: IdentityDict = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        Self::from_dict(&dict)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityDict {
    pub name: String,
    pub signing_private: String,
    pub agreement_private: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kem_public: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kem_private: Option<String>,
}

#[derive(Clone)]
pub struct Contact {
    pub name: String,
    pub signing_public: [u8; 32],
    pub agreement_public: [u8; 32],
    pub master_secret: [u8; 32],
    pub conversation_id: String,
    pub next_send_seq: u64,
    pub last_recv_seq: u64,
    pub contact_id: Option<[u8; 32]>,
    pub transcript_hash: Option<[u8; 32]>,
    pub ratchet: Option<RatchetState>,
    pub hybrid_pq: bool,
    pub session_started_at: u64,
    pub privacy_mode: String,
    pub mailbox_epoch_secs: u64,
}

impl Contact {
    pub fn establish_classical(local: &Identity, remote_name: &str, remote_bundle: &PublicBundle) -> Self {
        let remote_signing: [u8; 32] = b64decode(&remote_bundle.signing_public)
            .unwrap()
            .try_into()
            .unwrap();
        let remote_agreement: [u8; 32] = b64decode(&remote_bundle.agreement_public)
            .unwrap()
            .try_into()
            .unwrap();
        let shared = x25519_shared_secret(&local.agreement_private_bytes(), &remote_agreement);
        let master = derive_master_secret(&shared, b"");
        let conversation_id = conversation_id_for(&local.name, remote_name);
        let is_initiator = local.name.as_str() < remote_name;
        Self {
            name: remote_name.to_string(),
            signing_public: remote_signing,
            agreement_public: remote_agreement,
            master_secret: master,
            conversation_id,
            next_send_seq: 1,
            last_recv_seq: 0,
            contact_id: None,
            transcript_hash: None,
            ratchet: Some(RatchetState::from_master(&master, is_initiator, false)),
            hybrid_pq: false,
            session_started_at: 0,
            privacy_mode: crate::privacy::MODE_FAST.to_string(),
            mailbox_epoch_secs: 3600,
        }
    }

    pub fn to_dict(&self) -> ContactDict {
        ContactDict {
            name: self.name.clone(),
            signing_public: b64encode(&self.signing_public),
            agreement_public: b64encode(&self.agreement_public),
            master_secret: b64encode(&self.master_secret),
            conversation_id: self.conversation_id.clone(),
            next_send_seq: self.next_send_seq,
            last_recv_seq: self.last_recv_seq,
            contact_id: self.contact_id.map(|b| b64encode(&b)),
            transcript_hash: self.transcript_hash.map(|b| b64encode(&b)),
            ratchet: self.ratchet.as_ref().map(|r| serde_json::to_string(&r.to_dict()).unwrap()),
            hybrid_pq: if self.hybrid_pq { 1 } else { 0 },
            session_started_at: self.session_started_at,
            privacy_mode: if self.privacy_mode == crate::privacy::MODE_FAST {
                None
            } else {
                Some(self.privacy_mode.to_string())
            },
            mailbox_epoch_secs: self.mailbox_epoch_secs,
        }
    }

    pub fn from_dict(dict: &ContactDict) -> Result<Self, String> {
        let ratchet = dict
            .ratchet
            .as_ref()
            .map(|raw| {
                let parsed: crate::ratchet::RatchetDict =
                    serde_json::from_str(raw).map_err(|e| e.to_string())?;
                RatchetState::from_dict(&parsed)
            })
            .transpose()?;
        Ok(Self {
            name: dict.name.clone(),
            signing_public: b64decode(&dict.signing_public)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "signing_public")?,
            agreement_public: b64decode(&dict.agreement_public)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "agreement_public")?,
            master_secret: b64decode(&dict.master_secret)
                .map_err(|e| e.to_string())?
                .try_into()
                .map_err(|_| "master_secret")?,
            conversation_id: dict.conversation_id.clone(),
            next_send_seq: dict.next_send_seq,
            last_recv_seq: dict.last_recv_seq,
            contact_id: dict
                .contact_id
                .as_ref()
                .map(|v| b64decode(v).unwrap().try_into().unwrap()),
            transcript_hash: dict
                .transcript_hash
                .as_ref()
                .map(|v| b64decode(v).unwrap().try_into().unwrap()),
            ratchet,
            hybrid_pq: dict.hybrid_pq != 0,
            session_started_at: dict.session_started_at,
            privacy_mode: dict
                .privacy_mode
                .clone()
                .unwrap_or_else(|| crate::privacy::MODE_FAST.to_string()),
            mailbox_epoch_secs: dict.mailbox_epoch_secs,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContactDict {
    pub name: String,
    pub signing_public: String,
    pub agreement_public: String,
    pub master_secret: String,
    pub conversation_id: String,
    #[serde(default = "default_one")]
    pub next_send_seq: u64,
    #[serde(default)]
    pub last_recv_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transcript_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet: Option<String>,
    #[serde(default)]
    pub hybrid_pq: u32,
    #[serde(default)]
    pub session_started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_mode: Option<String>,
    #[serde(default = "default_epoch_secs")]
    pub mailbox_epoch_secs: u64,
}

fn default_one() -> u64 {
    1
}

fn default_epoch_secs() -> u64 {
    3600
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicBundle {
    pub name: String,
    pub signing_public: String,
    pub agreement_public: String,
}

pub fn export_public_bundle(identity: &Identity) -> PublicBundle {
    PublicBundle {
        name: identity.name.clone(),
        signing_public: b64encode(&identity.signing_public_bytes()),
        agreement_public: b64encode(&identity.agreement_public_bytes()),
    }
}

pub fn conversation_id_for(a: &str, b: &str) -> String {
    let (left, right) = if a < b { (a, b) } else { (b, a) };
    format!("pairwise_{left}_{right}")
}

pub fn contact_id_for(signing_public: &[u8], agreement_public: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(signing_public);
    hasher.update(agreement_public);
    hasher.finalize().into()
}
