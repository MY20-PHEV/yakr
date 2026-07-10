//! Cryptographic primitives for [Yakr Protocol](https://github.com/yakr-protocol/yakr) v1.0.
//!
//! Independent of the Python `yakr-core` package. Conformance is checked against
//! `docs/spec/test-vectors-v1/`.

pub mod aead;
pub mod cbor;
pub mod delivery_profile;
pub mod encoding;
pub mod hkdf;
pub mod hybrid;
pub mod inner_message;
pub mod invite;
pub mod mailbox;
pub mod master;
pub mod x25519;

pub use aead::{xchacha_decrypt, xchacha_encrypt, AeadError};
pub use delivery_profile::verify_delivery_profile;
pub use hybrid::derive_hybrid_master;
pub use inner_message::{
    message_id, verify_inner_message_json, InnerMessage, InnerMessageError, InnerMessageFields,
    MessageType,
};
pub use invite::{derive_safety_code, verify_invite_bundle};
pub use mailbox::{derive_mailbox_secret, derive_mailbox_tag};
pub use master::{derive_master_secret, derive_message_key};
pub use x25519::{generate_keypair as x25519_generate_keypair, shared_secret as x25519_shared_secret};
