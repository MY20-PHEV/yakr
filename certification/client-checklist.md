# Yakr Certified — Client v1.0 checklist

Copy into your certification application. Mark each item **pass** / **fail** / **n/a** with evidence (test name, vector file, or one-line note).

## Pairing and crypto

- [ ] Invite pairing (classical `yakr-v0.4`) completes inviter + joiner roles
- [ ] Pairing transcript matches `docs/spec/test-vectors-v1/pairing_transcript.json`
- [ ] Double ratchet bootstrap matches `double_ratchet.json` on normative pairing path
- [ ] `verify_all_vectors()` passes without importing `yakr_core` (or equivalent port)
- [ ] Negative vectors in `test-vectors-v1/negative/` reject as specified

## Wire formats

- [ ] Inner `text` JSON canonical form (`inner_message.json`)
- [ ] Inner `receipt` JSON + `message_id` derivation (`inner_receipt.json`)
- [ ] Outer relay blob JSON round-trip (`outer_blob.json`)
- [ ] Invite + delivery profile verify (`invite.json`, `delivery_profile.json`)
- [ ] Mailbox tag derivation (`mailbox_tag.json`)

## Delivery

- [ ] Fetch algorithm: out-of-order relay blobs do not drop messages ([fetch-algorithm.md](../docs/spec/fetch-algorithm.md))
- [ ] Delivery receipts clear `outbound_pending` only on verified E2E receipt
- [ ] Receive path uses outbound poll (no inbound listener required on mobile)

## Relay authorization

- [ ] Advertises only relays permitted by [relay-authorization.md](../docs/spec/relay-authorization.md)
- [ ] Does not use open global relay directories or anonymous public mailboxes

## Optional extensions (separate badge lines)

- [ ] Hybrid PQ pairing (`yakr-v0.6`)
- [ ] Minimal presence (`presence-minimal.md`)
- [ ] Pairing-anchored TLS (`tls-endpoints.md`)
- [ ] Platform wake (`platform-wake-v1.md`) — poll remains required

## Product metadata

- **Product name:**
- **Repository / download URL:**
- **Platforms:**
- **Crypto libraries used:**
