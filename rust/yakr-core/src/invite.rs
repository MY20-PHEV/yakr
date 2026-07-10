use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::Signer;
use rand::RngCore;

use crate::hybrid_pq::HYBRID_PQ_CAPABILITY;
use crate::identity::Identity;
use crate::message::{b64decode, b64encode};

pub const PROTOCOL_V4: &str = "yakr-v0.4";
pub const PROTOCOL_V6: &str = "yakr-v0.6";
pub const DEFAULT_INVITE_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
pub struct InviteBundle {
    pub protocol: String,
    pub inviter_name: String,
    pub signing_public: [u8; 32],
    pub agreement_public: [u8; 32],
    pub invite_secret: [u8; 32],
    pub rendezvous_hint: String,
    pub expires_at: u64,
    pub capabilities: Vec<String>,
    pub signature: Vec<u8>,
    pub kem_public: Vec<u8>,
}

pub fn invite_supports_hybrid(bundle: &InviteBundle) -> bool {
    bundle.capabilities.iter().any(|c| c == HYBRID_PQ_CAPABILITY) && !bundle.kem_public.is_empty()
}

pub fn create_invite(
    identity: &Identity,
    rendezvous_hint: &str,
    ttl_ms: u64,
    hybrid_pq: bool,
) -> Result<InviteBundle, String> {
    let mut capabilities = vec![
        "direct_p2p".into(),
        "friend_relay".into(),
        "store_forward".into(),
    ];
    let mut protocol = PROTOCOL_V4.to_string();
    let mut kem_public = Vec::new();
    if hybrid_pq {
        if identity.kem_public.is_empty() {
            return Err("identity missing ML-KEM keypair for hybrid invite".into());
        }
        protocol = PROTOCOL_V6.to_string();
        capabilities.push(HYBRID_PQ_CAPABILITY.into());
        kem_public = identity.kem_public.clone();
    }
    let mut invite_secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut invite_secret);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let mut bundle = InviteBundle {
        protocol,
        inviter_name: identity.name.clone(),
        signing_public: identity.signing_public_bytes(),
        agreement_public: identity.agreement_public_bytes(),
        invite_secret,
        rendezvous_hint: rendezvous_hint.to_string(),
        expires_at: now + ttl_ms,
        capabilities,
        signature: Vec::new(),
        kem_public,
    };
    let unsigned = invite_unsigned_cbor(&bundle)?;
    bundle.signature = identity.signing_key().sign(&unsigned).to_bytes().to_vec();
    Ok(bundle)
}

pub fn verify_invite(bundle: &InviteBundle) -> Result<(), String> {
    if !yakr_crypto::verify_invite_bundle(
        &invite_to_b64(bundle)?,
        &hex::encode(bundle.signing_public),
        &safety_code(&bundle.signing_public, &bundle.agreement_public),
    ) {
        return Err("invite verification failed".into());
    }
    Ok(())
}

pub fn safety_code(signing_public: &[u8], agreement_public: &[u8]) -> String {
    yakr_crypto::derive_safety_code(signing_public, agreement_public)
}

pub fn invite_to_b64(bundle: &InviteBundle) -> Result<String, String> {
    Ok(b64encode(&invite_to_bytes(bundle)?))
}

pub fn invite_from_b64(value: &str) -> Result<InviteBundle, String> {
    invite_from_bytes(&b64decode(value).map_err(|e| e.to_string())?)
}

fn invite_unsigned_cbor(bundle: &InviteBundle) -> Result<Vec<u8>, String> {
    use ciborium::value::Value;
    yakr_crypto::cbor::encode_cbor(&Value::Map(invite_unsigned_map(bundle)?))
        .map_err(|e| format!("{e:?}"))
}

pub fn invite_to_bytes(bundle: &InviteBundle) -> Result<Vec<u8>, String> {
    use ciborium::value::Value;
    let mut map = invite_unsigned_map(bundle)?;
    map.push((
        Value::Text("signature".into()),
        Value::Bytes(bundle.signature.clone()),
    ));
    yakr_crypto::cbor::encode_cbor(&Value::Map(map)).map_err(|e| format!("{e:?}"))
}

fn invite_unsigned_map(bundle: &InviteBundle) -> Result<Vec<(ciborium::value::Value, ciborium::value::Value)>, String> {
    use ciborium::value::Value;
    let mut entries = vec![
        (Value::Text("protocol".into()), Value::Text(bundle.protocol.clone())),
        (Value::Text("inviter_name".into()), Value::Text(bundle.inviter_name.clone())),
        (Value::Text("signing_public".into()), Value::Bytes(bundle.signing_public.to_vec())),
        (Value::Text("agreement_public".into()), Value::Bytes(bundle.agreement_public.to_vec())),
        (Value::Text("invite_secret".into()), Value::Bytes(bundle.invite_secret.to_vec())),
        (Value::Text("rendezvous_hint".into()), Value::Text(bundle.rendezvous_hint.clone())),
        (Value::Text("expires_at".into()), Value::Integer((bundle.expires_at as i64).into())),
    ];
    let caps: Vec<Value> = bundle
        .capabilities
        .iter()
        .map(|c| Value::Text(c.clone()))
        .collect();
    entries.push((Value::Text("capabilities".into()), Value::Array(caps)));
    if !bundle.kem_public.is_empty() {
        entries.push((
            Value::Text("kem_public".into()),
            Value::Bytes(bundle.kem_public.clone()),
        ));
    }
    Ok(entries)
}

pub fn invite_from_bytes(data: &[u8]) -> Result<InviteBundle, String> {
    let value = yakr_crypto::cbor::decode_cbor(data).map_err(|e| format!("{e:?}"))?;
    let map = value.as_map().ok_or("invite not a map")?;
    let get_bytes = |key: &str| -> Result<Vec<u8>, String> {
        yakr_crypto::cbor::map_bytes(&value, key).ok_or_else(|| format!("missing {key}"))
    };
    let get_text = |key: &str| -> Result<String, String> {
        match yakr_crypto::cbor::map_field(&value, key) {
            Some(ciborium::value::Value::Text(s)) => Ok(s.clone()),
            _ => Err(format!("missing {key}")),
        }
    };
    let caps = yakr_crypto::cbor::map_field(&value, "capabilities")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| match v {
                    ciborium::value::Value::Text(s) => Some(s.clone()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(InviteBundle {
        protocol: get_text("protocol")?,
        inviter_name: get_text("inviter_name")?,
        signing_public: get_bytes("signing_public")?.try_into().map_err(|_| "signing_public")?,
        agreement_public: get_bytes("agreement_public")?
            .try_into()
            .map_err(|_| "agreement_public")?,
        invite_secret: get_bytes("invite_secret")?.try_into().map_err(|_| "invite_secret")?,
        rendezvous_hint: get_text("rendezvous_hint")?,
        expires_at: match yakr_crypto::cbor::map_field(&value, "expires_at") {
            Some(ciborium::value::Value::Integer(v)) => i128::from(*v) as u64,
            _ => return Err("missing expires_at".into()),
        },
        capabilities: caps,
        signature: get_bytes("signature")?,
        kem_public: yakr_crypto::cbor::map_bytes(&value, "kem_public").unwrap_or_default(),
    })
}
