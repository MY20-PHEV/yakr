# Independent Review — Phase 11 Implementation Readiness (11 July 2026)

**Status:** Reference (not normative)  
**Source:** Independent review of the live repository ([MY20-PHEV/yakr](https://github.com/MY20-PHEV/yakr)) with Phase 11 as the main lens  
**Audience:** Project maintainers; informs post–Phase 11 hardening and certification trust signalling  
**Predecessors:** [external-critique-2026-07-10.md](./external-critique-2026-07-10.md), [github-follow-up-critique-2026-07-10.md](./github-follow-up-critique-2026-07-10.md), [external-ratchet-review-f16-issue-2-2026-07-11.md](./external-ratchet-review-f16-issue-2-2026-07-11.md)  
**Milestone reviewed:** [phase-11-implementation-readiness.md](../spec/phase-11-implementation-readiness.md)  
**Steward response:** [§ Steward response](#steward-response-2026-07-11)

---

## Overall conclusion

Phase 11 is **credibly complete**. Yakr has crossed from “a protocol design with two codebases” into “an independently implementable protocol with meaningful cross-language evidence.”

**Verdict:** Phase 11 passes review. No issue comparable to F16; no reason to downgrade the milestone from complete.

The reviewer does **not** recommend reopening Phase 11. Several follow-up items deserve attention before the project presents itself too confidently to outside implementers.

---

## Main findings

### 1. Medium — live Python↔Rust interop tests appear classical-only

This is the most important remaining **technical** qualification.

**WP2 genuinely exercises both implementation directions:**

- Python inviter → Rust joiner
- Rust inviter → Python joiner
- real pairing artefacts
- message upload through a relay
- cross-language fetch and decrypt

That is strong evidence. The cross-language harness is built into CI and implementation work fixed a real Rust mailbox-tag derivation disagreement along the way.

**However**, the test setup in WP2 explicitly creates classical identities and invokes Rust with `--classical`.

**Strongest current evidence:**

> Python and Rust interoperate over the complete normative pairing/ratchet/message path in **classical mode**.

The hybrid path has vectors and parity work, but the reviewer did **not** see equivalent end-to-end Python↔Rust live pairing tests using the post-quantum path.

This does **not** invalidate Phase 11. The milestone wording required Python↔Rust interoperability in both role directions, and that has been demonstrated.

Because Yakr presents itself prominently as post-quantum, the reviewer recommends:

> Add live Python inviter ↔ Rust joiner and Rust inviter ↔ Python joiner tests using hybrid PQ pairing.

That would close the gap between “hybrid vectors agree” and “hybrid implementations actually interoperate through the complete workflow.”

**Classification:** Phase 11 follow-up, not a blocker.

---

### 2. Medium — opening paid certification immediately may be ahead of external trust maturity

Technically, the certification programme is clearly described as protocol conformance, not a security guarantee. Documentation retains important warnings:

- security maturity is experimental
- composition has not been externally audited
- production use is not recommended

That is responsible.

The concern is mainly **reputational and governance-related**.

The programme now:

- accepts applications
- publishes commercial fees
- grants badge use
- includes a public implementer directory
- lists the Yakr reference CLI and relay as steward self-certified implementations

All of that is legitimate, but an external reader may interpret “Yakr Protocol Certified” as stronger than intended, particularly while the protocol is still experimental and externally unaudited.

**Recommendations:**

1. Add a prominent statement beside every certification badge and directory entry:

   > Certification indicates interoperability and protocol-conformance review only. It is not a security audit, product endorsement, or assurance of production suitability.

2. Avoid making the reference implementation’s “self-certification” visually equivalent to an independently reviewed third-party implementation. Suggested label:

   > **Reference baseline — steward maintained**

   rather than “Certified” in exactly the same sense.

**Classification:** trust-signalling hygiene, not a protocol flaw.

---

### 3. Low — “all normative wire structures have frozen vectors” is defensible, but scope should stay bounded

Phase 11 now includes:

- pairing transcript vectors
- double-ratchet bootstrap and message vectors
- outer-blob vectors
- inner-receipt vectors
- existing invite, profile, mailbox-tag and message vectors
- published negative vectors

The milestone documentation marks all seven exit criteria complete.

The claim is reasonable in the context of the declared v1.0 conformance surface.

**Wording guard:** “all normative wire structures” may be read by a new implementer as:

> every field, extension, profile update, relay capability, TLS lifecycle structure and operational interaction has exhaustive frozen vectors.

**Better description:**

> All normative **core v1.0 interoperability structures** required by the Phase 11 implementation-readiness profile have frozen vectors.

That remains a strong claim and is more future-proof.

---

### 4. Low — negative vectors are valuable; rejection semantics could become more precise

**WP4** moved important failure cases out of internal pytest tests into public artefacts. The pack covers:

- hybrid downgrade/missing KEM cases
- invite secret disagreement
- missing ratchet keys
- malformed CBOR
- tampered invite signatures
- malformed ratchet headers
- duplicate ratchet messages
- excessive skip gaps
- tampered ciphertext

**Next maturity improvement:** every negative vector should specify not only:

- `must_reject: true`
- `error_contains: "..."`

but also:

- `rejection_stage`
- `normative_error_code`
- `persistent_state_must_change: false`
- `retryable: false`

Human-readable exception substrings are useful for the current verifier, but implementation-language-specific. A Rust, Go or Swift implementation should not have to reproduce Python exception text to be considered conforming. The **protocol-level outcome** matters more than the wording.

---

### 5. Low — CI evidence described in repo; independent green-status verification unavailable

The repository changes clearly add Rust build and cross-language execution to the CI workflow.

The reviewer could not independently verify current green status through the GitHub connector at review time. That does not mean CI failed — only that independent status evidence was unavailable from the response.

**Satisfied with:** the design of the CI gate.  
**Not claimed:** personal verification that the latest workflow run was green.

---

## What Phase 11 did particularly well

### Rust is now a meaningful independent implementation

WP1 was not merely adding equivalent function names. It implemented:

- ratchet public keys in the transcript
- joiner receive-side pairing initialisation
- inviter deferred send-side initialisation
- decrypt rollback
- skipped-key bounds
- pairing transcript vectors
- double-ratchet vectors

That is a substantial independent reproduction of the protocol’s hardest stateful area. WP2 then found and corrected a Rust mailbox-tag derivation issue — exactly the kind of divergence Phase 11 was meant to expose.

### Interop testing is stronger than simple vector comparison

The cross-language test path creates identities, exchanges invite/pairing artefacts, persists contacts, sends through the relay, fetches and decrypts. That gives confidence in:

- serialisation
- role assignment
- transcript agreement
- ratchet bootstrap
- mailbox derivation
- persisted state
- relay envelope compatibility

### Delivery semantics are now protocol, not implementation folklore

Promoting the delivery state machine to normative status was the correct move. The document links atomic send state, receive state, receipt persistence, rollback and fetch behaviour, and records the remaining process-level crash test as erratum rather than pretending it is complete.

### The errata register is excellent

[errata-v1.md](../spec/errata-v1.md) distinguishes:

- genuine v1 clarification
- non-normative helper behaviour
- operational gaps
- deferred v1.1 work
- resolved findings

The explicit treatment of `Contact.establish()` is particularly important.

### The README is now much better for public visibility

The merged README redesign gives a newcomer:

- a plain-language description
- the maturity warning
- the core differentiator
- a simple message flow
- the protocol/product boundary
- role-specific navigation

That was the right change before bringing more outside attention to the project.

---

## Current maturity assessment

| Area | Assessment |
|------|------------|
| Core protocol concept | Strong and distinctive |
| Normative documentation | Strong for an experimental project |
| Python reference | Broad and mature |
| Rust independence | Now meaningful |
| Classical cross-language interop | Strong evidence |
| Hybrid PQ cross-language interop | Vector evidence; live E2E parity should be added |
| Conformance vectors | Strong core coverage |
| Negative testing | Good foundation |
| Delivery semantics | Properly normative |
| Security maturity | Still experimental |
| External cryptographic confidence | Limited; no formal audit |
| Third-party implementation readiness | Credibly achieved |
| Production readiness | Correctly not claimed |

---

## Recommended next focus

Do **not** immediately invent another large feature phase.

Create a short **post–Phase 11 hardening cycle** with four bounded items:

1. **Hybrid Python↔Rust live interop** — both inviter directions; actual ML-KEM/hybrid path; send, fetch, reply and persisted restart
2. **Protocol-level negative outcomes** — replace reliance on exception substrings with normative rejection identifiers and state-change expectations
3. **Certification trust wording** — make “conformance, not security audit” prominent; distinguish steward reference baseline from independently reviewed products
4. **Fresh external review package** — present completed Phase 11 artefacts; ask an outsider to implement or verify one slice without reading either reference implementation

**Most valuable next test:**

> Give an independent developer only the normative specs, vectors and conformance documentation, and see where they become confused.

That validates the Phase 11 claim better than adding another internal implementation feature.

---

## Final verdict (reviewer)

| Item | Conclusion |
|------|------------|
| Phase 11 milestone | **Passes review** — credibly complete |
| Reopen Phase 11? | **No** |
| Largest technical opportunity | Live hybrid-PQ Python↔Rust interoperability |
| Largest nontechnical risk | Certification language interpreted as security assurance |
| Public exposure readiness | Genuinely strong position for first wider exposure |

---

## Steward response (2026-07-11)

**Accepted:** Phase 11 remains **complete**. This review is saved as reference input to a bounded post–Phase 11 hardening cycle — not a new protocol phase.

| Finding | Steward position | Tracking |
|---------|------------------|----------|
| Classical-only live cross-lang interop | **Resolved (P11-1).** Hybrid PQ live E2E in both directions with reply + persisted restart. | Done — [test_phase11_cross_lang.py](../../packages/yakr-testkit/tests/test_phase11_cross_lang.py) |
| Certification trust signalling | **Accepted.** Conformance ≠ security audit must be impossible to miss on badges and directory entries; steward listings should not look identical to third-party certification. | P11-3; [CERTIFICATION.md](../../CERTIFICATION.md), [certification/IMPLEMENTERS.md](../../certification/IMPLEMENTERS.md) |
| “All normative wire structures” wording | **Accepted.** Milestone docs will use bounded “core v1.0 interoperability structures” language. | [phase-11-implementation-readiness.md](../spec/phase-11-implementation-readiness.md) exit criterion #3 |
| Negative vector protocol-level outcomes | **Resolved (P11-2).** [negative-vector-outcomes-v1.md](../spec/negative-vector-outcomes-v1.md) | Done |
| CI green status not independently verified | **Noted.** Steward maintains CI gates; public badge/README may link to workflow status when useful. | — |
| Blind external implementation test | **Resolved (P11-4).** [interop/blind-review/](../../interop/blind-review/) — awaiting external reviewer | Done |

**Not planned:** Reopening Phase 11 exit criteria or delaying certification applications solely on hybrid live interop — hybrid live E2E is now covered in CI (P11-1 complete).

See [phase-11-implementation-readiness.md § Post–Phase 11 hardening](../spec/phase-11-implementation-readiness.md#postphase-11-hardening).
