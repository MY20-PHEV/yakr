# Relay Authorization (Delivery Profiles)

**Status:** Implemented  
**Protocol:** `yakr-v0.5` delivery profiles

## Rule

A peer MAY advertise a relay in its **own** signed delivery profile only if:

1. **Self-operated relay** — `YAKR_RELAY_URL` is set and `YAKR_RELAY_NAME` matches the local identity name, or
2. **Paired relay operator** — the relay descriptor is copied from a **contact** who operates that relay (`descriptor.name == contact.name`).

Bob cannot claim reachability via Charlie's relay unless Bob is paired with Charlie (the operator).

## Using vs advertising

| Action | Requires pairing with relay operator? |
|--------|--------------------------------------|
| Use relay as **rendezvous** for invites | No |
| **Advertise** relay in your profile | Yes |
| **Send to** a contact via their advertised relay | No (use their signed profile) |
| **Store for** a contact on your paired relay when they advertise none | Yes (sender's paired relay) |
| **Fetch** from a contact's advertised relay | No |

## Implementation

- `yakr_core.relay_authorization` — `authorized_publish_relays()`, `assert_publish_relays_allowed()`
- `yakr profile publish` — builds descriptors from paired operators + optional self relay
- `deliver_encrypted()` — recipient mailboxes first, then sender's paired relays; `YAKR_RELAY_URL` as operational fallback for dev/CLI only (not published)

## Exit criteria

- [x] Profile publish rejects unpaired relay advertisement
- [x] Alice→Bob via sender's paired relay when Bob advertises no relay
- [x] Bob→Alice via Alice's advertised relay without Bob–Charlie pairing
- [x] Testkit `test_relay_rendezvous.py`
