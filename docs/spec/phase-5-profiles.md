# Phase 5 — Delivery Profiles

**Protocol:** `yakr-v0.5`  
**Status:** Implemented

## Goal

Each contact publishes a signed delivery profile describing how to reach them when direct delivery fails.

## Profile Contents

- Relay descriptors (entry/mailbox URLs and wrap secrets)
- Direct P2P hints (`http://host:port`)
- Mailbox epoch parameters
- Receipt policy and blob size classes

## Commands

```bash
# Publish or refresh your local profile
yakr profile publish --direct-port 18100

# Inspect local or contact profile
yakr profile show
yakr profile show bob

# Push profile update to a contact
yakr profile push alice
```

Send and fetch automatically use the contact's stored delivery profile. Direct hints are tried first (2s timeout), then relay descriptors.

## Sender fallback acknowledgement

When Alice uses **her own** operator mailboxes as sender fallback (because Bob
advertises none, or his mailboxes are unreachable), she may only try relays Bob
has acknowledged:

| Event | Effect on Bob's view |
|-------|----------------------|
| Pairing | Initial `delivery_profile` bytes exchanged; counts as ack |
| `yakr profile push bob` | Encrypted profile message; receipt updates ack |
| Inbound `type=profile` on fetch | Recipient updates contact profile |

Until Bob acknowledges profile version *N*, relays introduced in that version
are not eligible sender fallbacks for messages to Bob. Recipient mailboxes from
Bob's own profile are always tried first and are unaffected.

Implemented in `yakr_core/profile_ack.py` and `delivery_mailbox_urls()`.

## Exit Criteria

- [x] Bob updates profile; Alice uses new mailbox relay without manual config edit
- [x] Stale profile attempt logs warning and retries after refresh
- [x] Direct P2P success bypasses relay when both CLIs online on LAN
