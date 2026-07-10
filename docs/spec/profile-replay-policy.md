# Delivery Profile Replay Policy

**Protocol:** `yakr-v1.0`  
**Status:** Normative  
**Related:** [delivery-state-machine.md](./delivery-state-machine.md), [fetch-algorithm.md](./fetch-algorithm.md)

## Purpose

Signed `DeliveryProfile` inner messages share the contact `seq` counter with `text`, `receipt`, and `presence`. A relay observer or peer MUST NOT be able to roll back a recipient to an older relay set by replaying a previously valid profile blob.

## Threat model

| Attacker capability | Goal |
|---------------------|------|
| Relay stores old profile ciphertext | Force recipient onto deprecated relays |
| Peer replays captured profile update | Downgrade TLS pins or mailbox routing |

Profiles are signed by the peer's long-term Ed25519 signing key. Forgery without key compromise is out of scope; **version rollback of legitimately signed older profiles** is in scope.

## Normative rules

When processing inbound `inner.type == "profile"` after successful `decrypt_outer`:

1. **Verify** signature with `verify_delivery_profile(profile, contact.signing_public)`.
2. **Reject expired** profiles (`valid_until < now`) — do not merge.
3. **Monotonic version** — if `contact.delivery_profile` exists:
   - Accept when `incoming.version > stored.version`.
   - Accept when `incoming.version == stored.version` and bytes are identical (idempotent replay).
   - **Reject** when `incoming.version < stored.version` (rollback).
   - **Reject** when `incoming.version == stored.version` but content differs (version conflict).
4. **Persist receive state** — even when merge is rejected, implementations MUST `save_contact` after `decrypt_outer` so `last_recv_seq` and receive ratchet state reflect the consumed `seq`. Do not skip seq advancement for rejected profiles.

Initial pairing MAY install `version == 1` (or higher) without a stored profile. Profile publish commands bump version on each intentional update.

## Reference API

- `accept_delivery_profile_update(current, incoming)` — anti-replay check only
- `apply_delivery_profile_update(contact, profile, signing_public)` — verify + accept + assign

## Exit criteria (tests)

- Rollback of `v1` while stored `v2` is rejected
- Fetch of replayed old profile advances `last_recv_seq` but leaves stored profile at `v2`
- Same-version identical profile is idempotent

## References

- `packages/yakr-core/src/yakr_core/delivery_profile.py`
- `packages/yakr-testkit/tests/test_profile_replay.py`
