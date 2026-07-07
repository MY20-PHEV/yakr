# Phase 3 — Path Rotation

**Protocol:** `yakr-v0.3`  
**Status:** Implemented

## Goal

Successive messages should not reuse the same entry/mailbox relay pair by default.

## Route Selection

```text
route_seed = HKDF(conversation_secret, message_id || "route")
```

Clients score `(entry, mailbox)` pairs, penalise recent reuse, and persist
`RouteState` per contact in `route_state.json`.

## CLI

```bash
yakr send bob "hello" --route auto
```

## Exit Criteria

- [x] 100 sequential messages across 4 relays show no immediate pair repeat
- [x] Route choices reproducible given `(conversation_secret, message_id)`
- [x] Route state persisted across CLI invocations
- [ ] Simulated relay failure triggers alternate route retry
