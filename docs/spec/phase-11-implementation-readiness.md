# Phase 11 — Yakr v1.0 Independent Implementation Readiness

**Protocol:** `yakr-v1.0`  
**Status:** Complete (WP1–WP5 + wire-structure vectors)  
**Depends on:** Phase 10 complete; F16/R6 closed on normative pairing path ([double-ratchet.md](./double-ratchet.md) § Session bootstrap paths)

## Goal

A third party can implement a **minimal Yakr v1.0 client** from public specifications and frozen vectors alone — without importing the Python reference library — and interoperate with both Python and Rust reference stacks on the **normative invite-pairing + double-ratchet** path.

Phase 9 proved a narrow crypto/encoding interop slice. Phase 11 closes the gap between “vectors for primitives” and “two independent implementations that pair and exchange messages.”

**In scope:** pairing transcript (Option B), ratchet bootstrap and message encrypt/decrypt, mailbox tag + outer blob relay path, delivery semantics normative status, published negative vectors, standalone conformance runner.

**Out of scope (tracked elsewhere):** external security audit, full CLI parity, multi-device, platform wake, Tor/mesh transports, `Contact.establish()` production path ([P2-8](../SECURITY_BACKLOG.md)). Certification program: [CERTIFICATION.md](../../CERTIFICATION.md) (**open**).

---

## Exit criteria

| # | Criterion | Status | Notes |
|---|-----------|--------|-------|
| 1 | Python and Rust implement the **same normative pairing and ratchet path** | **Done (WP1)** | Rust Option B parity; cross-lang CI in WP2 |
| 2 | **Python↔Rust interoperability** succeeds in **both role directions** (inviter/joiner × send/fetch) | **Done (WP2)** | Classical + **hybrid PQ** live E2E in `test_phase11_cross_lang.py`; CI |
| 3 | **Core v1.0 interoperability structures** in the Phase 11 profile have frozen vectors | **Done** | Pairing, ratchet, outer blob, receipt inner JSON in `interop_verifier`; bounded scope per [phase-11 critique](../reviews/phase-11-independent-critique-2026-07-11.md) |
| 4 | **Negative vectors** define rejection behaviour | **Done (WP4)** | `test-vectors-v1/negative/` + `verify_negative_vector` in `interop_verifier` |
| 5 | **Delivery semantics** are no longer draft | **Done (WP5)** | [delivery-state-machine.md](./delivery-state-machine.md) normative; aligned with [fetch-algorithm.md](./fetch-algorithm.md) |
| 6 | A third party can run the **conformance suite without importing `yakr_core`** | **Done** | `verify_all_vectors()` — 9 positive files + negative pack |
| 7 | Remaining ambiguities tracked as **errata or v1.1 work** | **Done (WP5)** | [errata-v1.md](./errata-v1.md) |

---

## Deliverables

| Artifact | Path / action |
|----------|----------------|
| Rust Option B parity | `rust/yakr-core/src/pairing.rs`, `ratchet.rs` |
| Cross-language interop tests | CI: Python inviter → Rust joiner and reverse; Rust→Python and Python→Rust send/fetch |
| Extended interop verifier | `packages/yakr-testkit/src/yakr_testkit/interop_verifier.py` — pairing transcript + double ratchet |
| Negative vector pack | `docs/spec/test-vectors-v1/negative/` (invite, profile, ratchet header, pairing transcript) |
| Delivery spec promotion | [delivery-state-machine.md](./delivery-state-machine.md) — **Normative** |
| Errata register | [errata-v1.md](./errata-v1.md) |
| Protocol §8 update | [yakr-protocol-v1.md](./yakr-protocol-v1.md) — full vector inventory |
| Rust CLI pairing | `yakr invite create` / `accept` (or documented pairing example binary) |

---

## Work packages (suggested order)

### WP1 — Rust normative path parity

1. Add `joiner_ratchet_public` to `PairingRequest`; include both ratchet publics in `pairing_transcript()`.
2. Port Option B bootstrap: joiner `_pairing_recv_init`, inviter deferred `_pairing_send_init` on first encrypt.
3. Port ratchet rollback semantics from Python (decrypt failure, receipt non-advancement).
4. `cargo test` against `pairing_transcript.json` and `double_ratchet.json` (vectors must pass).

### WP2 — Cross-language interop (CI)

1. Rust relay in-process or ephemeral port.
2. **Py inviter → Rust joiner** → Rust sends → Python fetches.
3. **Rust inviter → Py joiner** → Python sends → Rust fetches.
4. Repeat with hybrid PQ invite where ML-KEM parity is already pinned. **Done** — `test_hybrid_*_send_fetch_reply_restart`.

### WP3 — Conformance suite expansion

1. `verify_pairing_transcript_vector`, `verify_double_ratchet_vector` in `interop_verifier.py` (stdlib + `cryptography` only; no `yakr_core`).
2. Wire into `test_phase9_interop.py` and `verify_all_vectors()`.
3. Document run instructions in [interop/README.md](../../interop/README.md) for non-Python implementers (optional: thin shell wrapper that only needs Python 3 + pip deps, or publish equivalent in another language).

### WP4 — Negative vectors

1. Catalogue rejection cases from existing pytest adversarial tests.
2. Freeze as JSON: expected error class or boolean `must_reject: true` per case.
3. Verifier function: `verify_negative_vector` — implementation must reject without panic.

### WP5 — Delivery semantics + errata

1. Promote delivery state machine; resolve any conflicts with fetch algorithm. **Done**
2. Open `errata-v1.md`; link P2-8 (`establish` non-normative), draft extensions explicitly deferred to v1.1. **Done**

---

## Demo (target)

```bash
# Standalone conformance (no yakr_core)
uv run python -c "
from yakr_testkit.interop_verifier import verify_all_vectors
verify_all_vectors('docs/spec/test-vectors-v1')
"

# Cross-language (after WP2)
uv run pytest packages/yakr-testkit/tests/test_phase11_cross_lang.py -q
cd rust && cargo test cross_lang
```

---

## Relationship to certification

Phase 11 is complete. The [CERTIFICATION.md](../../CERTIFICATION.md) application process opened **2026-07-11**. Certification attests to wire compatibility, not production security maturity ([SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md)). Independent Phase 11 review: [phase-11-independent-critique-2026-07-11.md](../reviews/phase-11-independent-critique-2026-07-11.md).

---

## Post–Phase 11 hardening

Phase 11 exit criteria remain **closed**. The following bounded follow-ups are tracked from the [11 July 2026 independent review](../reviews/phase-11-independent-critique-2026-07-11.md) — not a new protocol phase.

| ID | Item | Status |
|----|------|--------|
| P11-1 | Live **hybrid PQ** Python↔Rust interop (both inviter directions; send/fetch/reply; restart) | **Done** — `test_phase11_cross_lang.py` |
| P11-2 | Negative vectors: `rejection_stage`, `normative_error_code`, `persistent_state_must_change`, `retryable` | **Done** — [negative-vector-outcomes-v1.md](../spec/negative-vector-outcomes-v1.md) |
| P11-3 | Certification trust wording: badge disclaimer; steward **reference baseline** label vs third-party certified | **Partial** — docs; badge assets open |
| P11-4 | External blind implementation package (spec + vectors only; no reference code) | **Done** — [interop/blind-review/](../../interop/blind-review/) |

---

## References

- [phase-9-interop.md](./phase-9-interop.md) — prior interop milestone (complete)
- [pairing-transcript-v1.md](./pairing-transcript-v1.md) — normative pairing
- [delivery-state-machine.md](./delivery-state-machine.md) — normative delivery
- [errata-v1.md](./errata-v1.md) — v1.0 clarifications and deferrals
- [rust/RUST_PORT.md](../../rust/RUST_PORT.md) — Rust gap analysis
