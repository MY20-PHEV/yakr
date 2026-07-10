//! X25519 double ratchet matching Python `yakr_core.ratchet`.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use serde::{Deserialize, Serialize};
use x25519_dalek::StaticSecret;
use yakr_crypto::{hkdf_sha256, xchacha_decrypt, xchacha_encrypt};

pub const RATCHET_MAGIC: &[u8; 5] = b"YKDR2";
const ROOT_INFO: &[u8] = b"yakr/v1.0/double-ratchet-root";
const RK_INFO: &[u8] = b"yakr/v1.0/double-ratchet-rk";
const CK_INFO: &[u8] = b"yakr/v1.0/double-ratchet-ck";
const SEND_CHAIN_INFO: &[u8] = b"yakr/v1.0/double-ratchet-send";
const RECV_CHAIN_INFO: &[u8] = b"yakr/v1.0/double-ratchet-recv";

fn hkdf64(ikm: &[u8], info: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("hkdf64");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8]) -> ([u8; 32], [u8; 32]) {
    hkdf64(root_key, RK_INFO, dh_output)
}

fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    hkdf64(chain_key, CK_INFO, b"")
}

fn shared_secret(private_key: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    yakr_crypto::x25519_shared_secret(private_key, peer_public)
}

fn b64encode(data: &[u8]) -> String {
    URL_SAFE.encode(data).trim_end_matches('=').to_string()
}

fn b64decode(value: &str) -> Vec<u8> {
    let rem = value.len() % 4;
    let padded = if rem == 0 {
        value.to_string()
    } else {
        format!("{value}{}", "=".repeat(4 - rem))
    };
    URL_SAFE.decode(padded).unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub dh_self_private: [u8; 32],
    pub dh_self_public: [u8; 32],
    pub dh_peer_public: Option<[u8; 32]>,
    pub send_chain_key: Option<[u8; 32]>,
    pub recv_chain_key: Option<[u8; 32]>,
    pub send_n: u32,
    pub recv_n: u32,
    pub prev_send_n: u32,
    pub skipped_keys: BTreeMap<String, String>,
    pub hybrid: bool,
}

#[derive(Serialize, Deserialize)]
pub struct RatchetDict {
    pub version: u32,
    pub root_key: String,
    pub dh_self_private: String,
    pub dh_self_public: String,
    #[serde(default)]
    pub dh_peer_public: String,
    #[serde(default)]
    pub send_chain_key: String,
    #[serde(default)]
    pub recv_chain_key: String,
    #[serde(default)]
    pub send_n: u32,
    #[serde(default)]
    pub recv_n: u32,
    #[serde(default)]
    pub prev_send_n: u32,
    #[serde(default)]
    pub skipped_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub hybrid: bool,
}

impl RatchetState {
    pub fn from_master(master_secret: &[u8; 32], is_initiator: bool, hybrid: bool) -> Self {
        let root_key = hkdf_sha256(master_secret, ROOT_INFO, b"");
        let mut send_chain = hkdf_sha256(&root_key, SEND_CHAIN_INFO, b"");
        let mut recv_chain = hkdf_sha256(&root_key, RECV_CHAIN_INFO, b"");
        if !is_initiator {
            std::mem::swap(&mut send_chain, &mut recv_chain);
        }
        let (dh_self_private, dh_self_public) = yakr_crypto::x25519_generate_keypair();
        Self {
            root_key,
            dh_self_private,
            dh_self_public,
            dh_peer_public: None,
            send_chain_key: Some(send_chain),
            recv_chain_key: Some(recv_chain),
            send_n: 0,
            recv_n: 0,
            prev_send_n: 0,
            skipped_keys: BTreeMap::new(),
            hybrid,
        }
    }

    pub fn to_dict(&self) -> RatchetDict {
        RatchetDict {
            version: 2,
            root_key: b64encode(&self.root_key),
            dh_self_private: b64encode(&self.dh_self_private),
            dh_self_public: b64encode(&self.dh_self_public),
            dh_peer_public: self
                .dh_peer_public
                .map(|k| b64encode(&k))
                .unwrap_or_default(),
            send_chain_key: self
                .send_chain_key
                .map(|k| b64encode(&k))
                .unwrap_or_default(),
            recv_chain_key: self
                .recv_chain_key
                .map(|k| b64encode(&k))
                .unwrap_or_default(),
            send_n: self.send_n,
            recv_n: self.recv_n,
            prev_send_n: self.prev_send_n,
            skipped_keys: self.skipped_keys.clone(),
            hybrid: self.hybrid,
        }
    }

    pub fn from_dict(dict: &RatchetDict) -> Result<Self, String> {
        if dict.version != 2 {
            return Err("unsupported ratchet version; re-pair required".into());
        }
        let peer = b64decode(&dict.dh_peer_public);
        let send = b64decode(&dict.send_chain_key);
        let recv = b64decode(&dict.recv_chain_key);
        Ok(Self {
            root_key: b64decode(&dict.root_key).try_into().map_err(|_| "root_key")?,
            dh_self_private: b64decode(&dict.dh_self_private)
                .try_into()
                .map_err(|_| "dh_self_private")?,
            dh_self_public: b64decode(&dict.dh_self_public)
                .try_into()
                .map_err(|_| "dh_self_public")?,
            dh_peer_public: if peer.len() == 32 {
                Some(peer.try_into().unwrap())
            } else {
                None
            },
            send_chain_key: if send.len() == 32 {
                Some(send.try_into().unwrap())
            } else {
                None
            },
            recv_chain_key: if recv.len() == 32 {
                Some(recv.try_into().unwrap())
            } else {
                None
            },
            send_n: dict.send_n,
            recv_n: dict.recv_n,
            prev_send_n: dict.prev_send_n,
            skipped_keys: dict.skipped_keys.clone(),
            hybrid: dict.hybrid,
        })
    }

    fn header_aad(&self, prev_n: u32, message_n: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + 32 + 8);
        out.extend_from_slice(RATCHET_MAGIC);
        out.extend_from_slice(&self.dh_self_public);
        out.extend_from_slice(&prev_n.to_be_bytes());
        out.extend_from_slice(&message_n.to_be_bytes());
        out
    }

    fn dh_ratchet(&mut self, peer_public: [u8; 32]) {
        self.dh_peer_public = Some(peer_public);
        let dh_output = shared_secret(&self.dh_self_private, &peer_public);
        let (root, recv) = kdf_rk(&self.root_key, &dh_output);
        self.root_key = root;
        self.recv_chain_key = Some(recv);
        self.recv_n = 0;

        let (new_private, new_public) = yakr_crypto::x25519_generate_keypair();
        self.dh_self_private = new_private;
        self.dh_self_public = new_public;
        let dh_output = shared_secret(&self.dh_self_private, &peer_public);
        let (root, send) = kdf_rk(&self.root_key, &dh_output);
        self.root_key = root;
        self.send_chain_key = Some(send);
        self.prev_send_n = self.send_n;
        self.send_n = 0;
    }

    fn store_skip(&mut self, peer_public: &[u8; 32], n: u32, message_key: [u8; 32]) {
        let key_id = format!("{}:{n}", hex::encode(peer_public));
        self.skipped_keys.insert(key_id, b64encode(&message_key));
    }

    fn skip_key(&self, peer_public: &[u8; 32], n: u32) -> Result<[u8; 32], ()> {
        let key_id = format!("{}:{n}", hex::encode(peer_public));
        let stored = self.skipped_keys.get(&key_id).ok_or(())?;
        let bytes = b64decode(stored);
        bytes.try_into().map_err(|_| ())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut send_chain = self.send_chain_key.ok_or("send chain not initialized")?;
        let (message_key, next_chain) = kdf_ck(&send_chain);
        self.send_chain_key = Some(next_chain);
        let aad = self.header_aad(self.prev_send_n, self.send_n);
        let ciphertext = xchacha_encrypt(&message_key, plaintext, &aad).map_err(|e| format!("{e:?}"))?;
        let mut out = Vec::with_capacity(5 + 32 + 8 + ciphertext.len());
        out.extend_from_slice(RATCHET_MAGIC);
        out.extend_from_slice(&self.dh_self_public);
        out.extend_from_slice(&self.prev_send_n.to_be_bytes());
        out.extend_from_slice(&self.send_n.to_be_bytes());
        out.extend_from_slice(&ciphertext);
        self.send_n += 1;
        Ok(out)
    }

    pub fn decrypt(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() < 5 + 32 + 8 {
            return Err("ratchet payload too short".into());
        }
        if &payload[..5] != RATCHET_MAGIC {
            return Err("invalid ratchet header".into());
        }
        let peer_public: [u8; 32] = payload[5..37].try_into().unwrap();
        let prev_n = u32::from_be_bytes(payload[37..41].try_into().unwrap());
        let message_n = u32::from_be_bytes(payload[41..45].try_into().unwrap());
        let ciphertext = &payload[45..];

        if self.dh_peer_public.is_none() {
            self.dh_peer_public = Some(peer_public);
        } else if self.dh_peer_public != Some(peer_public) {
            self.dh_ratchet(peer_public);
        }

        let mut recv_chain = self.recv_chain_key.ok_or("recv chain not initialized")?;
        let message_key = if message_n < self.recv_n {
            self.skip_key(&peer_public, message_n)
                .map_err(|_| "ratchet message already received".to_string())?
        } else {
            while self.recv_n < message_n {
                let (mk, next) = kdf_ck(&recv_chain);
                recv_chain = next;
                self.store_skip(&peer_public, self.recv_n, mk);
                self.recv_n += 1;
            }
            let (mk, next) = kdf_ck(&recv_chain);
            recv_chain = next;
            self.recv_n = message_n + 1;
            mk
        };
        self.recv_chain_key = Some(recv_chain);

        let mut aad = Vec::with_capacity(5 + 32 + 8);
        aad.extend_from_slice(RATCHET_MAGIC);
        aad.extend_from_slice(&peer_public);
        aad.extend_from_slice(&prev_n.to_be_bytes());
        aad.extend_from_slice(&message_n.to_be_bytes());
        xchacha_decrypt(&message_key, ciphertext, &aad).map_err(|e| format!("{e:?}"))
    }
}
