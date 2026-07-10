//! Cryptographic primitives for [Yakr Protocol](https://github.com/yakr-protocol/yakr) v1.0.
//!
//! Independent of the Python `yakr-core` package. Conformance is checked against
//! `docs/spec/test-vectors-v1/`.

pub mod hkdf;
pub mod hybrid;
pub mod mailbox;

pub use hybrid::derive_hybrid_master;
pub use mailbox::{derive_mailbox_secret, derive_mailbox_tag};
