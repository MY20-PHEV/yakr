# ADR 007: Presence Layer and Group Relay Polling

**Status:** Accepted (draft)  
**Date:** 2026-07-07

## Context

The whitepaper describes a social-relay model where friends’ devices can temporarily store encrypted blobs. The v1 reference implementation:

- Separates `yakr-relay` from clients
- Uses signed delivery profiles with multi-day TTL
- Does not advertise live relay availability to paired contacts
- Requires manual `profile publish` / `profile push` for route changes

Mobile-only friend groups need:

1. A **reachable group relay** for store-and-forward and poll-based fetch
2. **Ephemeral presence** so peers learn current reachability and relay willingness
3. Optional **embedded relay** on clients when policy allows

## Decision

Adopt a two-layer routing model for `yakr-v1.1`:

1. **Presence** — short-TTL encrypted `type=presence` inner messages between paired contacts
2. **Delivery profile** — existing signed CBOR for wrap secrets and long-term relay identity

Send and fetch algorithms prefer fresh presence, then profile, then shared **group relay** URLs for polling.

Every client MAY embed the relay HTTP API when `relay.active` is advertised. At least one group member (or their VPS) SHOULD run an always-reachable relay for **pairing rendezvous**, message store, and fetch polling.

**Implemented (pre-v1.1):** relay rendezvous (`/v1/pair*`) and relay authorization — peers may only advertise relays operated by paired contacts. See `docs/spec/relay-rendezvous.md` and `docs/spec/relay-authorization.md`.

## Consequences

**Positive**

- Matches user mental model: peers update each other dynamically
- Mobile recipients only need outbound HTTP (poll group relay)
- **One group relay URL for pairing + messaging** — no separate rendezvous host
- Opportunistic LAN relay via presence without profile churn
- Backward compatible: v1.0 clients ignore unknown inner message types

**Negative**

- More background traffic (presence refresh per contact)
- Embedded relay on mobile is hard on Android (NAT, battery, background limits)
- Routing logic becomes more complex
- Spec and test surface grows (Phase 10)

## Alternatives considered

| Alternative | Rejected because |
|-------------|------------------|
| Profile-only (frequent re-sign) | Too heavy; mixes slow trust anchor with fast reachability |
| Global presence server | Violates decentralisation / no global IDs principle |
| Push notifications only | Requires platform infra; poll-on-relay remains baseline |
| DHT discovery | Deferred; abuse and metadata concerns |

## References

- `docs/spec/presence-v1.md`
