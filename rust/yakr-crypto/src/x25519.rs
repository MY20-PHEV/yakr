//! X25519 key agreement.

use x25519_dalek::{PublicKey, StaticSecret};

/// Compute X25519 shared secret (32 bytes).
pub fn shared_secret(private_key: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let peer = PublicKey::from(*peer_public);
    secret.diffie_hellman(&peer).to_bytes()
}

/// Generate a random X25519 keypair (private, public).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}
