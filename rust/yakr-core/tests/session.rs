use yakr_core::{
    invite::create_invite,
    pairing::{build_pairing_request, inviter_complete_pairing, joiner_complete_pairing},
    ratchet::RATCHET_MAGIC,
    session::Session,
    store::FileLocalStore,
    Identity,
};
use yakr_crypto::x25519_generate_keypair;

#[test]
fn double_ratchet_bidirectional() {
    let alice = Identity::generate("alice", false);
    let bob = Identity::generate("bob", false);
    let invite = create_invite(&alice, "http://test", 60_000, false).unwrap();
    let (request, secrets) = build_pairing_request(&bob, &invite, "bob").unwrap();
    let (inviter_ephemeral, _) = x25519_generate_keypair();
    let (response, mut alice_contact) =
        inviter_complete_pairing(&alice, &invite, &request, inviter_ephemeral, None).unwrap();
    let mut bob_contact = joiner_complete_pairing(&bob, &invite, &request, &secrets, &response).unwrap();

    let mut alice_session = Session::new(alice, alice_contact).unwrap();
    let mut bob_session = Session::new(bob, bob_contact).unwrap();

    let first = alice_session.encrypt_text("hello bob").unwrap();
    assert!(first.outer_blob.ciphertext.starts_with(RATCHET_MAGIC));
    let inner = bob_session.decrypt_outer(&first.outer_blob).unwrap();
    assert_eq!(inner.body.as_deref(), Some("hello bob"));

    let reply = bob_session.encrypt_text("hello alice").unwrap();
    let back = alice_session.decrypt_outer(&reply.outer_blob).unwrap();
    assert_eq!(back.body.as_deref(), Some("hello alice"));

    let _ = alice_session.into_contact();
    let _ = bob_session.into_contact();
}

#[test]
fn ratchet_state_persists_via_store() {
    let tmp = tempfile::tempdir().unwrap();
    let store = FileLocalStore::new(tmp.path().join("bob"));
    let bob = Identity::generate("bob", false);
    store.save_identity(&bob).unwrap();

    let alice = Identity::generate("alice", false);
    let invite = create_invite(&alice, "http://test", 60_000, false).unwrap();
    let (request, secrets) = build_pairing_request(&bob, &invite, "bob").unwrap();
    let (ephemeral, _) = x25519_generate_keypair();
    let (response, _) = inviter_complete_pairing(&alice, &invite, &request, ephemeral, None).unwrap();
    let contact = joiner_complete_pairing(&bob, &invite, &request, &secrets, &response).unwrap();
    store.save_contact(&contact).unwrap();

    let reloaded = store.get_contact("alice").unwrap().unwrap();
    assert!(reloaded.ratchet.is_some());
    assert_eq!(reloaded.ratchet.as_ref().unwrap().to_dict().version, 2);
}

#[test]
fn mailbox_epoch_lookback() {
    use yakr_core::mailbox::MailboxTagDeriver;
    use yakr_crypto::derive_mailbox_secret;

    let master = [9u8; 32];
    let direction = "alice->bob";
    let secret = derive_mailbox_secret(&master, direction);
    let deriver = MailboxTagDeriver::new(secret, 3600);
    let tags = deriver.candidate_epochs(direction, 2);
    assert_eq!(tags.len(), 3);
}
