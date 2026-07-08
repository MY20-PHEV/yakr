# Phase 10 — Presence, TLS, and Relay Resilience

**Protocol:** `yakr-v1.0` + extensions  
**Status:** Partial (see exit criteria below)  
**Depends on:** Phase 9

## Goal

Enable reliable friend-group messaging with:

- **Live presence** — ephemeral reachability without re-signing profiles
- **Pairing-anchored TLS** — HTTPS everywhere, SPKI pins in signed profiles
- **Relay resilience** — ordered failover, resend, queued receipts

## Deliverables

```text
docs/spec/presence-minimal.md       implemented
docs/spec/tls-endpoints.md          implemented
docs/spec/relay-failover.md         implemented
docs/spec/presence-v1.md            full design (deferred)
packages/yakr-core/                 presence, TLS pins, receipt queue store
packages/yakr-cli/                  presence, receipts flush, resend
packages/yakr-testkit/              Charlie+Dennis mesh, TLS, outage tests
docs/demo-vps-charlie.md            HTTPS homelab workflow
```

## User-visible capability

```text
# HTTPS relay on VPS (pairing-anchored cert)
python scripts/generate_operator_relay_tls.py ~/.yakr/charlie
CHARLIE_TLS_DIR=~/.yakr/charlie/relay-tls ./scripts/deploy_charlie_vps.sh

# Operator IP change
yakr profile publish    # or yakr presence push

# Recovery after outage
yakr fetch bob
yakr receipts flush
yakr resend bob
```

## Exit criteria

- [x] `type=presence` inner messages (`presence-minimal.md`)
- [x] Routing: presence → profile URL
- [x] TLS SPKI pins on profiles and relay descriptors
- [x] Send failover + `yakr resend`
- [x] Queued receipts + `yakr receipts flush`
- [ ] Full `presence-v1.md` routing (group relays, embedded relay)
- [ ] `yakr fetch --all` without manual relay env
- [ ] Embedded relay when dialable (`reachable` required; LAN/IPv6 — see ADR 008)
- [ ] Five-client testkit matching VPS trust model (no Bob↔Charlie shortcut)
- [ ] Security analysis updated for presence metadata

## Spec

- [presence-minimal.md](presence-minimal.md) — implemented subset
- [presence-v1.md](presence-v1.md) — full future design
- [tls-endpoints.md](tls-endpoints.md)
- [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md)
