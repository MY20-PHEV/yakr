# Yakr Protocol v1.0 — Errata and Deferred Work

**Protocol:** `yakr-v1.0`  
**Status:** Living register (updated as ambiguities are resolved or deferred)  
**Precedence:** Below [yakr-protocol-v1.md](./yakr-protocol-v1.md) and other normative `docs/spec/` documents; above [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) narrative backlog.

This document records **known gaps**, **non-normative helpers**, and **explicit v1.1 deferrals** so independent implementers do not infer requirements from reference-only code paths or draft extension specs.

---

## Errata (v1.0 clarifications)

| ID | Topic | v1.0 position | Tracking |
|----|-------|---------------|----------|
| **E-001** | `Contact.establish()` bootstrap | **Non-normative.** Production clients MUST use invite pairing ([double-ratchet.md](./double-ratchet.md) § Session bootstrap paths). `establish()` is for tests, mesh fixtures, `contact-add`, and local dev — symmetric chains only, no transcript-bound ratchet publics, no pairing-time DH init. | [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-8 |
| **E-002** | Process-level crash (`kill -9`) | Atomic send/receive commits are **normative** and implemented in the reference store ([delivery-state-machine.md](./delivery-state-machine.md) §Crash safety). End-to-end `kill -9` injection across OS process boundaries is **not** yet a conformance requirement. | [delivery-state-machine.md](./delivery-state-machine.md) exit criteria |
| **E-003** | Relay blob delete on fetch | v1 relays **MUST NOT** delete blobs on `GET`. Retention is TTL sweep only. Optional operator delete-after-receipt policies require a new API and grace period. | [delivery-state-machine.md](./delivery-state-machine.md) §Relay answers |
| **E-004** | TLS pin `revoked_pins[]` | Profile-carried SPKI pins and rotation overlap are normative ([tls-pin-lifecycle.md](./tls-pin-lifecycle.md)). An explicit `revoked_pins` list in signed profiles is **not** in v1.0 wire format; compromise recovery uses versioned profile supersede. | [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P0-9 |
| **E-005** | Double ratchet audit status | Pairing-path Option B is normative and interop-tested. The ratchet remains **experimental; not externally audited** ([double-ratchet.md](./double-ratchet.md)). | [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-1, P2-7 |

---

## Deferred to v1.1 or later (not v1.0 requirements)

| ID | Topic | Draft / ADR | Notes |
|----|-------|-------------|-------|
| **D-001** | Live presence + group relay polling | [presence-v1.md](./presence-v1.md) | v1.0 uses [presence-minimal.md](./presence-minimal.md) only |
| **D-002** | Platform silent wake | [platform-wake-v1.md](./platform-wake-v1.md), [ADR 011](../adr/011-platform-wake.md) | Fetch algorithm unchanged when wake is added |
| **D-003** | Multi-device sync | [multi-device.md](./multi-device.md) | v1.0: one device per identity for delivery state |
| **D-004** | Tor transport | [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) | Explicit deferral |
| **D-005** | Meshtastic / LoRaWAN | [ADR 010](../adr/010-offline-mesh-transports.md) | Explicit deferral |
| **D-006** | Ephemeral cloud relay deploy | [ADR 009](../adr/009-ephemeral-cloud-relay.md) | Explicit deferral |

---

## Resolved (closed on v1.0 path)

| ID | Topic | Resolution |
|----|-------|------------|
| **R-001** | F16 / R6 pairing vs `establish` DH epoch | Closed on **normative invite-pairing path** (Option B). `establish` remains non-normative per E-001. |
| **R-002** | PQ downgrade on hybrid invites | `validate_pairing_request_for_invite` + negative vectors |
| **R-003** | Delivery state machine draft status | Promoted to **normative** — [delivery-state-machine.md](./delivery-state-machine.md) (Phase 11 WP5) |

---

## How to use this register

1. **Implementing v1.0:** Follow `yakr-protocol-v1.md`, normative specs under `docs/spec/`, frozen vectors, and [fetch-algorithm.md](./fetch-algorithm.md) + [delivery-state-machine.md](./delivery-state-machine.md) for delivery.
2. **Seeing `Contact.establish` in reference tests:** Allowed for harnesses; do not ship as production pairing (E-001).
3. **Proposing a spec change:** Open a PR updating the normative doc **and** this errata (resolve → move row to Resolved; defer → Deferred; clarify → Errata).
4. **Certification:** Conformance suites MUST NOT require behaviour marked Deferred unless a future protocol revision promotes it.

---

## References

- [phase-11-implementation-readiness.md](./phase-11-implementation-readiness.md)
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md)
- [double-ratchet.md](./double-ratchet.md) § Session bootstrap paths
