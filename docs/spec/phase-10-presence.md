# Phase 10 — Presence and Group Relay Polling

**Protocol:** `yakr-v1.1` (proposed)  
**Status:** Not started  
**Depends on:** Phase 9

## Goal

Enable friend groups to message reliably with:

- **Live presence** — paired peers exchange reachability and embedded relay status
- **Group relay polling** — shared reachable relay for offline store-and-forward
- **Embedded client relay** — optional policy-gated relay API on any peer

## Deliverables

```text
docs/spec/presence-v1.md              normative extension (draft)
packages/yakr-core/                   type=presence, PresencePayload, routing
packages/yakr-mobile/                 embedded relay + presence push on policy change
packages/yakr-cli/                    presence push/show, embedded relay mode
packages/yakr-testkit/                five-peer group sim, one VPS relay
```

## User-visible capability

```text
# Dennis runs group relay on VPS
yakr-relay serve --port 443 --data-dir ./data

# Charlie on home Wi‑Fi enables embedded relay
yakr relay embed --port 18100 --wifi-only

# Presence auto-pushed to contacts; friends poll Dennis for messages
yakr fetch --all   # polls group relays from presence + profile
```

## Exit criteria

- [ ] `type=presence` inner messages parsed and routed per `presence-v1.md`
- [ ] Sender tries presence → profile → group relay in normative order
- [ ] FetchWorker polls shared group relay without manual `YAKR_RELAY_URL`
- [ ] Embedded relay on mobile when `relay_enabled` + Wi‑Fi/charging gates pass
- [ ] Five-client testkit: four phones + one VPS relay; offline delivery via poll
- [ ] Security analysis updated for presence metadata

## Spec

See [presence-v1.md](presence-v1.md) and [ADR 007](../adr/007-presence-and-group-relays.md).
