# Security and Protocol Hardening Backlog

**Status:** Living document  
**Source:** [External review 2026-07-10](reviews/external-critique-2026-07-10.md), [GitHub follow-up 2026-07-10](reviews/github-follow-up-critique-2026-07-10.md), [Phase 11 review 2026-07-11](reviews/phase-11-independent-critique-2026-07-11.md)  
**Purpose:** Track P0–P3 work before new transports or features

## Maturity labels (project-wide)

| Label | Current status |
|-------|----------------|
| Reference implementation breadth | Phases 1–10 largely complete |
| Protocol stability | Draft (`yakr-v1.0` frozen for interop; extensions in flight) |
| Security maturity | **Experimental** — not production-audited |
| External audit | Not performed |
| Production recommendation | **No** |

---

## P0 — Protocol correctness (attack first)

| ID | Item | Spec / tracking | Status |
|----|------|-----------------|--------|
| P0-1 | Formal delivery state machine | [delivery-state-machine.md](spec/delivery-state-machine.md) | **Normative** (Phase 11 WP5) |
| P0-2 | Transactional ratchet + outbound queue persist | [delivery-state-machine.md](spec/delivery-state-machine.md) §Crash safety | **Implemented** (`atomic_commit_send`) |
| P0-3 | Transactional receive decrypt + `last_recv_seq` persist | Same | **Implemented** (`atomic_commit_receive_text`) |
| P0-4 | Crash injection tests (send + receive) | `test_delivery_persistence.py`, `test_receive_crash_recovery.py` | **Done** (rollback, receipt queue, fetch flush recovery) |
| P0-5 | Document relay retention: TTL-only delete (not fetch/receipt) | [ephemeral-messages.md](spec/ephemeral-messages.md), state machine | Documented |
| P0-6 | Concurrent fetch serialization policy | `FileLocalStore.fetch_lock()` | **Implemented** (CLI, mesh, mobile) |
| P0-7 | Stale receipt handling normative test | `test_fetch_hardening.py`, `test_receipt_apply.py` | **Implemented** |
| P0-8 | Profile rollback / replay protection audit | [profile-replay-policy.md](spec/profile-replay-policy.md) | **Implemented** |
| P0-9 | TLS pin rotation + relay key compromise recovery | [tls-pin-lifecycle.md](spec/tls-pin-lifecycle.md) | **Done** (playbook, rotation + compromise recovery tests; explicit `revoked_pins[]` still future) |

## P1 — Identity and authorisation privacy

| ID | Item | Notes | Status |
|----|------|-------|--------|
| P1-1 | Replace stable `contact_id` in relay tickets | [ADR 012](adr/012-relay-capability-tokens.md), [relay-capability-v1.md](spec/relay-capability-v1.md) | **Done** (auto-detect; homelab `--require-capabilities`; tickets bootstrap-only) |
| P1-2 | Per-relay pseudonymous capability tokens | ADR 012 + `derive_capability_material` | **Done** (profile rotation + E2E supersede/overlap) |
| P1-3 | Separate operator identity from relay client capability | [operator-identity-v1.md](spec/operator-identity-v1.md) | **Done** |
| P1-4 | Relay-observer privacy table | [relay-observer-privacy-v1.md](spec/relay-observer-privacy-v1.md) | **Done** |
| P1-5 | `POST /v1/fetch` (tags in body, not URL path) | Reduces infra log leakage | **Done** (default; `YAKR_LEGACY_GET_FETCH=1` for GET) |
| P1-6 | Capability / wake token revocation lifecycle | [platform-wake-v1.md](spec/platform-wake-v1.md) | **Partial** (capability overlap + revoke; wake spec only) |

## P2 — Cryptographic protocol review

| ID | Item | Status |
|----|------|--------|
| P2-1 | Independent session / ratchet review | [session-ratchet-review-v1.md](security/session-ratchet-review-v1.md) | **Partial** — F16 closed (pairing path); see P2-8 for `establish` |
| P2-8 | `Contact.establish` vs pairing parity | [double-ratchet.md](spec/double-ratchet.md) § Session bootstrap paths | **Open** — migrate to Option B bootstrap or deprecate for production |
| P2-2 | Complete pairing transcript construction doc | [pairing-transcript-v1.md](spec/pairing-transcript-v1.md) | **Done** (normative spec, classical + hybrid vectors, transport equivalence tests) |
| P2-3 | PQ downgrade prevention (no silent classical after hybrid) | **Done** — `validate_pairing_request_for_invite` |
| P2-4 | Protocol version downgrade policy | **Done** — `invite.protocol` in transcript |
| P2-5 | Skipped-key limits + DoS bounds | [double-ratchet.md](spec/double-ratchet.md) | **Done** (`MAX_SKIP_GAP`/`MAX_SKIPPED_KEYS` + tests) |
| P2-6 | Malicious-input test vectors + CBOR fuzz | `test_cbor_fuzz.py`, dict guards on CBOR parsers | **Done** |
| P2-7 | Label ratchet "experimental, not audited" in docs | **Done** — `double-ratchet.md` |

## P3 — Real mobile evidence

| ID | Item | Status |
|----|------|--------|
| P3-1 | Physical Android delivery delay matrix (Doze, kill, reboot) | Open |
| P3-2 | Battery / wake reliability with optional platform wake | Depends on ADR 011 impl |
| P3-3 | QR byte budget for hybrid PQ invites | Open |
| P3-4 | Duplicate count under flaky network | Open |

---

## Easy doc fixes (from review)

| Item | Status |
|------|--------|
| Phase 5 heading in REFERENCE_DESIGN | Done |
| Whitepaper abstract vs single-hop default | Done |
| Whitepaper TTL examples → 24h normative | Done |
| Whitepaper roadmap defers to REFERENCE_DESIGN | Done |
| Maturity banner in README / CERTIFICATION | Done |
| Soften relay identity prose in whitepaper §3.1 | Done |
| Save external critique | [reviews/external-critique-2026-07-10.md](reviews/external-critique-2026-07-10.md) |
| Save GitHub follow-up critique | [reviews/github-follow-up-critique-2026-07-10.md](reviews/github-follow-up-critique-2026-07-10.md) |
| Save Phase 11 independent critique | [reviews/phase-11-independent-critique-2026-07-11.md](reviews/phase-11-independent-critique-2026-07-11.md) |
| Apache-2.0 code licence + CC BY docs | [LICENSE](../LICENSE), [DOCUMENTATION-LICENSE.md](DOCUMENTATION-LICENSE.md) |
| Document precedence in README | Done |
| SECURITY.md vulnerability reporting | [SECURITY.md](../SECURITY.md) |

---

## Phase 11 — Independent implementation readiness

**Milestone:** [phase-11-implementation-readiness.md](spec/phase-11-implementation-readiness.md)  
**Focus:** Rust Option B parity, cross-lang CI, extended `interop_verifier`, negative vectors, delivery spec promotion, `errata-v1.md`.

| Work package | Ties to backlog |
|--------------|-----------------|
| WP1 Rust pairing/ratchet parity | P2-1 (complete second implementation) |
| WP2 Cross-lang interop CI | **Done** — `test_phase11_cross_lang.py` |
| WP3 Conformance suite | **Done** — pairing + ratchet in `interop_verifier` |
| WP4 Negative vectors | P2-6 extension — **Done** |
| WP5 Delivery + errata | P0-1 — **Done** |
| Wire-structure vectors | `outer_blob.json`, `inner_receipt.json` — **Done** |

---

## Post–Phase 11 hardening (milestone closed)

**Review:** [phase-11-independent-critique-2026-07-11.md](reviews/phase-11-independent-critique-2026-07-11.md)  
**Tracking:** [phase-11-implementation-readiness.md § Post–Phase 11 hardening](spec/phase-11-implementation-readiness.md#postphase-11-hardening)

| ID | Item | Status |
|----|------|--------|
| P11-1 | Hybrid PQ live Python↔Rust interop (both inviter directions) | **Open** |
| P11-2 | Protocol-level negative vector outcomes (not exception substrings) | **Open** |
| P11-3 | Certification trust wording + steward reference-baseline label | **Open** |
| P11-4 | Blind external implementation review package | **Open** |

---

## Explicit deferrals (do not start until P0–P1 progress)

- Tor transport
- Meshtastic / LoRaWAN ([ADR 010](adr/010-offline-mesh-transports.md))
- Ephemeral cloud deploy ([ADR 009](adr/009-ephemeral-cloud-relay.md))
- Multi-device sync ([multi-device.md](spec/multi-device.md))
