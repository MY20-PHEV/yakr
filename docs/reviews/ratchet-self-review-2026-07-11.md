# Ratchet Self-Review — 2026-07-11

**Scope:** P2-1 internal assessment before external cryptographer engagement  
**Reviewer:** Reference implementation maintainers (not independent)  
**Package:** [session-ratchet-review-v1.md](../security/session-ratchet-review-v1.md)

This document records **self-review findings**. It does **not** satisfy P2-1 exit criteria for independent sign-off.

## Summary

The double ratchet implementation is **coherent and test-backed** for the reference client's threat model, with explicit DoS bounds and session-layer rollback. Several items from the July 2026 critique are **addressed in tests**; others remain **open design questions** suitable for external review.

**Recommendation:** Safe to invite external review using the P2-1 package. Do **not** claim production crypto maturity until a third party publishes findings.

## Findings

| ID | Topic | Result | Action |
|----|-------|--------|--------|
| F1 | Out-of-order wire `message_n` | **Pass** | Skipped keys within bounds; covered by adversarial tests |
| F2 | Application `inner.seq` strictness | **Pass** | Rollback on non-next seq prevents ratchet drift |
| F3 | Skip-gap DoS | **Pass** | `MAX_SKIP_GAP` / `MAX_SKIPPED_KEYS` enforced |
| F4 | DH ratchet on new peer public | **Pass** | Clears skipped keys; state advances |
| F5 | Duplicate `message_n` | **Pass** | Rejected via skipped-key miss |
| F6 | Same `dh_public` twice | **Pass** | No redundant DH step |
| F7 | Tampered ciphertext / AAD | **Pass** | AEAD failure |
| F8 | Malformed header | **Pass** | Short header / bad magic rejected |
| F9 | Bidirectional concurrent send | **Pass** | E2E tests; DH steps occur on both sides |
| F10 | Receipt send ratchet rollback | **Pass** | `test_receipt_failure_restores_ratchet` |
| F11 | X25519 public key validation | **Open** | No explicit low-order point rejection; rely on library |
| F12 | `prev_n` semantic binding | **Open** | In AAD only; not checked against peer `prev_send_n` |
| F13 | Post-compromise security | **N/A** | Not a design goal in v1.0 |
| F14 | Formal verification | **Open** | No machine-checked model |
| F15 | Rust port as security proof | **N/A** | Interop aid only per critique |
| F16 | DH ratchet activation in live traffic | **Open / High** | `_dh_ratchet` not reached in bidirectional ping-pong; only symmetric chain advances (`test_bidirectional_ping_pong_uses_symmetric_chain_only`) |

## Critique traceability

Source: [github-follow-up-critique-2026-07-10.md](./github-follow-up-critique-2026-07-10.md) §"Ratchet correctness beyond persistence"

| Critique item | Status |
|---------------|--------|
| Out-of-order delivery | Addressed (ratchet + session policy documented) |
| Skipped-key limits | Done (P2-5) |
| Maliciously huge sequence gaps | Addressed |
| DH-ratchet transitions | Partial | Symmetric chain advances; DH epoch may not rotate in ping-pong |
| Duplicate DH public keys | Addressed |
| Malformed public keys | Partial (F11 open) |
| Concurrent sends | Addressed (bidirectional tests) |
| Key deletion | Documented as chain advance + DH step; not proved |
| Post-compromise recovery claims | Correctly **not** claimed |

## Suggested external review focus

1. Soundness of `KDF-RK` / chain HKDF labels vs standard double-ratchet literature (Signal, RFC drafts).
2. Whether `prev_n` omission from peer cross-check enables an attack when combined with malicious relay reordering.
3. X25519 edge cases with attacker-controlled `dh_public` in headers.
4. Interaction between ratchet wire reorder and strict `inner.seq` under active relay (fetch loop correctness).

## Next steps

- [ ] Engage independent cryptographer or publish open review call
- [ ] Optional: add `prev_n` validation if review recommends
- [ ] Optional: ProVerif/Tamarin model (out of scope for reference impl unless funded)
