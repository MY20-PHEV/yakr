# Phase 4 — Invites and Relay Authorization

**Protocol:** `yakr-v0.4`  
**Status:** Implemented

## Goal

Replace pre-shared contact files with invite-based pairing and signed relay tickets.

## Invite Flow

```bash
# Alice
yakr invite create --port 8090

# Bob
yakr invite accept "yakr://invite/..."
```

Both sides display the same safety code for out-of-band verification.

## Relay Tickets

When relays run with `--require-tickets`, clients must attach signed tickets:

```bash
export YAKR_REQUIRE_TICKETS=1
export YAKR_RELAY_NAME=relay
```

## Exit Criteria

- [x] Invite URL pairing without pre-shared public.json files
- [x] Matching safety codes on inviter and joiner
- [x] Relay rejects blobs without valid tickets when required
- [x] Consumed invite cannot be replayed
- [x] Ratchet state persists across contact reload
