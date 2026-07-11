use std::fs;
use std::path::PathBuf;

use yakr_core::{
    invite::{create_invite, invite_from_bytes, invite_to_bytes},
    pairing::{
        build_pairing_request, inviter_complete_pairing, joiner_complete_pairing,
        pairing_request_from_bytes, pairing_request_to_bytes, pairing_response_from_bytes,
        pairing_response_to_bytes, PairingSecretsFile,
    },
    Identity,
};
use yakr_crypto::x25519_generate_keypair;

use crate::{b64decode_str, b64encode, load_identity, store_at};

pub fn run_init(name: &str, home: Option<PathBuf>, force: bool, classical: bool) -> Result<(), String> {
    let store = store_at(home, name);
    if store.identity_path().exists() && !force {
        return Err(format!(
            "identity already exists at {}",
            store.identity_path().display()
        ));
    }
    let identity = Identity::generate(name, !classical);
    store.save_identity(&identity)?;
    println!("initialized '{name}' at {}", store.root.display());
    Ok(())
}

pub fn run_create_invite(
    home: Option<PathBuf>,
    name: &str,
    rendezvous: &str,
    out: &PathBuf,
    classical: bool,
) -> Result<(), String> {
    let store = store_at(home, name);
    let identity = load_identity(&store)?;
    let invite = create_invite(&identity, rendezvous, 60_000, !classical)?;
    let bytes = invite_to_bytes(&invite)?;
    fs::write(out, b64encode(&bytes)).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn run_joiner_request(
    home: Option<PathBuf>,
    name: &str,
    invite_path: &PathBuf,
    out_request: &PathBuf,
    out_secrets: &PathBuf,
) -> Result<(), String> {
    let store = store_at(home, name);
    let identity = load_identity(&store)?;
    let invite = invite_from_bytes(&b64decode_file(invite_path)?)?;
    let (request, secrets) = build_pairing_request(&identity, &invite, name)?;
    fs::write(out_request, b64encode(&pairing_request_to_bytes(&request)?))
        .map_err(|e| e.to_string())?;
    let secrets_json = serde_json::to_string_pretty(&PairingSecretsFile::from_secrets(&secrets))
        .map_err(|e| e.to_string())?;
    fs::write(out_secrets, secrets_json).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn run_joiner_complete(
    home: Option<PathBuf>,
    name: &str,
    invite_path: &PathBuf,
    request_path: &PathBuf,
    secrets_path: &PathBuf,
    response_path: &PathBuf,
) -> Result<(), String> {
    let store = store_at(home, name);
    let identity = load_identity(&store)?;
    let invite = invite_from_bytes(&b64decode_file(invite_path)?)?;
    let request = pairing_request_from_bytes(&b64decode_file(request_path)?)?;
    let secrets_raw = fs::read_to_string(secrets_path).map_err(|e| e.to_string())?;
    let secrets_file: PairingSecretsFile =
        serde_json::from_str(&secrets_raw).map_err(|e| e.to_string())?;
    let secrets = secrets_file.to_secrets()?;
    let response = pairing_response_from_bytes(&b64decode_file(response_path)?)?;
    let contact = joiner_complete_pairing(&identity, &invite, &request, &secrets, &response)?;
    store.save_contact(&contact)?;
    println!("paired with {}", contact.name);
    Ok(())
}

pub fn run_inviter_complete(
    home: Option<PathBuf>,
    name: &str,
    invite_path: &PathBuf,
    request_path: &PathBuf,
    out_response: &PathBuf,
) -> Result<(), String> {
    let store = store_at(home, name);
    let identity = load_identity(&store)?;
    let invite = invite_from_bytes(&b64decode_file(invite_path)?)?;
    let request = pairing_request_from_bytes(&b64decode_file(request_path)?)?;
    let (inviter_ephemeral, _) = x25519_generate_keypair();
    let (response, contact) =
        inviter_complete_pairing(&identity, &invite, &request, inviter_ephemeral, None)?;
    fs::write(
        out_response,
        b64encode(&pairing_response_to_bytes(&response)?),
    )
    .map_err(|e| e.to_string())?;
    store.save_contact(&contact)?;
    println!("paired with {}", contact.name);
    Ok(())
}

fn b64decode_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    b64decode_str(raw.trim())
}
