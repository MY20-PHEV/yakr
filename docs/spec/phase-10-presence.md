# Phase 10 — Presence, TLS, and Relay Resilience

**Protocol:** `yakr-v1.0` + extensions  
**Status:** Complete (ADR 009 cloud deploy deferred to future work)  
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
docs/spec/presence-v1.md            routing subset implemented (group relay poll, embed)
packages/yakr-core/                 presence, TLS pins, receipt queue store, reachability
packages/yakr-cli/                  fetch --all, relay embed, presence, receipts flush, resend
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
yakr fetch --all
yakr receipts flush
yakr resend bob

# LAN embedded relay (foreground; dialable URL only)
yakr relay embed --host 0.0.0.0 --port 8090
```

## Exit criteria

- [x] `type=presence` inner messages (`presence-minimal.md`)
- [x] Routing: presence → profile URL
- [x] TLS SPKI pins on profiles and relay descriptors
- [x] Send failover + `yakr resend`
- [x] Queued receipts + `yakr receipts flush`
- [x] Full `presence-v1.md` routing (group relays via presence cache + trust graph poll)
- [x] `yakr fetch --all` without manual relay env
- [x] Embedded relay when dialable (`yakr relay embed`; ADR 008 reachable + relay_active gating)
- [x] Five-client testkit matching VPS trust model (no Bob↔Charlie shortcut)
- [x] Security analysis updated for presence metadata
- [ ] Ephemeral cloud relay deploy (`yakr relay deploy` / ADR 009)

## Spec

- [presence-minimal.md](presence-minimal.md) — implemented subset
- [presence-v1.md](presence-v1.md) — full future design
- [tls-endpoints.md](tls-endpoints.md)
- [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md)
