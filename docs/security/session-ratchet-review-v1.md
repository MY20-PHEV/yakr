# Session and Double-Ratchet — External Review Package

**Protocol:** `yakr-v1.0`  
**Status:** Review package (P2-1) — **not externally signed off**  
**Date:** 2026-07-11  
**Normative wire spec:** [double-ratchet.md](../spec/double-ratchet.md)  
**Pairing input:** [pairing-transcript-v1.md](../spec/pairing-transcript-v1.md)  
**Implementation:** `packages/yakr-core/src/yakr_core/ratchet.py`, `session.py`

## Purpose

This document packages everything an independent cryptographer needs to review Yakr's **ongoing message session** after pairing: the X25519 double ratchet, skipped-key policy, and how the `Session` layer binds application sequence numbers to ratchet state.

It does **not** replace a formal proof or paid audit. It maps review questions from [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md) to normative behaviour, test coverage, and known limitations.

## Architecture

```text
Pairing master_secret
        │
        ▼
RatchetState.from_master (HKDF root + send/recv chains + DH keypair)
        │
        ▼
Session.encrypt_text / decrypt_outer
        │  InnerMessage (JSON) + privacy padding
        ▼
RatchetState.encrypt / decrypt  (YKDR2 header + XChaCha20-Poly1305)
        │
        ▼
OuterBlob.ciphertext → relay mailbox
```

Two independent sequence spaces:

| Counter | Layer | Purpose |
|---------|-------|---------|
| `message_n` | Ratchet header | Per-chain message keys; supports wire-level out-of-order within bounds |
| `inner.seq` | Application (`InnerMessage`) | Strict `last_recv_seq + 1`; enforced in `Session.decrypt_outer` |

Wire-level reordering MAY succeed at the ratchet while application-level reordering is **rejected** with ratchet rollback. See [fetch-algorithm.md](../spec/fetch-algorithm.md).

## Bootstrap from `master_secret` (normative)

```text
root_key     = HKDF-SHA256(master_secret, info = "yakr/v1.0/double-ratchet-root", salt = "", len = 32)
send_chain   = HKDF-SHA256(root_key, info = "yakr/v1.0/double-ratchet-send", ...)
recv_chain   = HKDF-SHA256(root_key, info = "yakr/v1.0/double-ratchet-recv", ...)
```

Initiator (inviter in pairing, or lexicographically smaller name in `Contact.establish`) keeps `(send_chain, recv_chain)`. Joiner swaps chains.

Each side generates a fresh X25519 ratchet keypair `(dh_self_private, dh_self_public)`. `dh_peer_public` starts unset until the first received header.

Deterministic vector: [double_ratchet.json](../spec/test-vectors-v1/double_ratchet.json) (bootstrap + header fields; AEAD ciphertext is nonce-random per message).

## Wire header (normative)

```text
YKDR2 (5) | dh_public (32) | prev_n (u32 BE) | message_n (u32 BE) | XChaCha ciphertext
```

AAD for AEAD:

```text
YKDR2 || dh_public || BE_u32(prev_n) || BE_u32(message_n)
```

Note: encrypt uses **sender's** `dh_self_public` in the header; decrypt uses **header's** `dh_public` as peer public for chain lookup and DH steps.

## Symmetric chain step

```text
message_key, next_chain_key = HKDF-SHA256(chain_key, info = "yakr/v1.0/double-ratchet-ck", salt = "", len = 64)
```

## DH ratchet step (normative)

Triggered when incoming `dh_public` ≠ stored `dh_peer_public` **after** the first message (`dh_peer_public` was already set).

1. `skipped_keys.clear()`
2. `dh_peer_public ← header dh_public`
3. `RK, recv_chain ← KDF-RK(root, DH(dh_self_private, dh_peer_public))`; `recv_n ← 0`
4. Generate new `dh_self` keypair
5. `RK, send_chain ← KDF-RK(root, DH(new_dh_self_private, dh_peer_public))`; `prev_send_n ← send_n`; `send_n ← 0`

```text
KDF-RK(root, dh_out) = split(HKDF-SHA256(root, info = "yakr/v1.0/double-ratchet-rk", salt = dh_out, len = 64))
```

## Skipped keys and DoS bounds

| Constant | Value | On violation |
|----------|-------|--------------|
| `MAX_SKIP_GAP` | 128 | `ValueError("ratchet skip gap too large")` |
| `MAX_SKIPPED_KEYS` | 256 | `ValueError("ratchet skipped key limit exceeded")` |

When `message_n < recv_n`, decrypt looks up `(dh_public.hex(), message_n)` in `skipped_keys`. Missing entry → `ValueError("ratchet message already received")` → `DuplicateSeqError` at session layer.

## Session-layer receive policy (normative)

`Session.decrypt_outer`:

1. Snapshot ratchet state and `last_recv_seq`
2. Ratchet decrypt
3. Parse inner JSON, verify `conversation_id`
4. Require `inner.seq == last_recv_seq + 1` (strict in-order at application layer)
5. On any failure after ratchet advance: **rollback** ratchet snapshot (inner seq unchanged)

Mapped errors:

| Condition | Error |
|-----------|-------|
| Duplicate ratchet `message_n` | `DuplicateSeqError` |
| AEAD / padding / conversation mismatch | `DecryptError` |
| `inner.seq` not next | `DuplicateSeqError` (with rollback) |
| Expired `valid_until` | `MessageExpiredError` (with rollback) |

## Review question matrix

| Question (from critique) | Answer | Evidence |
|--------------------------|--------|----------|
| Out-of-order wire delivery | Supported within `MAX_SKIP_GAP` at ratchet; application seq still strict | `test_ratchet_adversarial.py`, `double-ratchet.md` |
| Skipped-key DoS | Bounded storage and gap | `test_ratchet_skipped_key_limits.py` |
| Malicious huge sequence gaps | Rejected before chain walk | `test_ratchet_rejects_excessive_skip_gap` |
| DH-ratchet transitions | Code path exists on new peer `dh_public` | `test_dh_ratchet_step_advances_state` (direct call); **F16:** not observed in ping-pong traffic |
| Duplicate DH public keys | No second DH step; same chain continues | `test_repeated_peer_dh_public_skips_ratchet` |
| Malformed public keys | X25519 accepts any 32-byte string; low-order points not explicitly rejected | **Open** — see self-review |
| Concurrent sends (both sides) | Each send advertises new `dh_self_public`; peer DH-steps on receive | `test_double_ratchet_bidirectional` |
| Key deletion / forward secrecy | Chain keys advanced per message; skipped keys cleared on DH step | Design intent; **not formally proved** |
| Post-compromise recovery | **Not claimed** — no SPQR-style recovery; re-pair or PQ rekey policy only | `hybrid_pq.needs_pq_rekey` |
| Persistence vs crypto | Atomic store commits separate concern (P0-2/3) | `test_delivery_persistence.py` |

## Security properties

### Claimed (pending external validation)

| Property | Mechanism |
|----------|-----------|
| Confidentiality | XChaCha20-Poly1305 per ratchet message key |
| Integrity | AEAD + AAD binds header to ciphertext |
| Forward secrecy (per message) | Chain key ratchet; DH step mixes new ephemeral DH |
| Replay at ratchet layer | Duplicate `message_n` under same `dh_public` rejected |
| Replay at application layer | Strict `inner.seq` |

### Not claimed

| Property | Notes |
|----------|-------|
| Post-compromise security | No break-in recovery beyond re-pairing |
| MLS / group security | Pairwise only |
| Metadata privacy | Mailbox tags, sizes, timing visible to relays |
| Quantum resistance (ongoing) | Hybrid master helps pairing; classical DH still used in ratchet DH steps |

## Known limitations and open items

| ID | Item | Severity | Notes |
|----|------|----------|-------|
| R1 | X25519 public key validation | Low–Med | Invalid curve points not rejected; libs may clamp |
| R2 | `prev_n` not cross-checked | Low | Header field included in AAD but not validated against peer state |
| R3 | Post-compromise recovery | Info | Documented deferral; PQ rekey is time/count policy not PCS |
| R4 | Rust/Python parity | Med | Independent impl exists; security review ≠ language port |
| R5 | No formal model | Info | No ProVerif/Tamarin artifact |
| R6 | DH ratchet not reached in normal ping-pong | **High** | Root/`dh_self` fixed; forward secrecy within epoch relies on symmetric chain only — see F16 |

Internal findings: [ratchet-self-review-2026-07-11.md](../reviews/ratchet-self-review-2026-07-11.md).

## Test coverage map

| File | Focus |
|------|-------|
| `test_ratchet_adversarial.py` | Malformed wire, reorder, DH step, tampering |
| `test_ratchet_skipped_key_limits.py` | DoS bounds |
| `test_double_ratchet_vectors.py` | Frozen bootstrap + first message |
| `test_ephemeral_double_ratchet.py` | End-to-end bidirectional + relay |
| `test_fetch_hardening.py` | Receipt ratchet rollback, concurrent fetch |
| `test_delivery_persistence.py` | Crash-safe commit paths |

## Reviewer workflow

1. Read this document and [double-ratchet.md](../spec/double-ratchet.md).
2. Recompute [double_ratchet.json](../spec/test-vectors-v1/double_ratchet.json) and [pairing_transcript.json](../spec/test-vectors-v1/pairing_transcript.json).
3. Walk `pairing_transcript()` → `RatchetState.from_master` → `encrypt`/`decrypt` in `pairing.py` / `ratchet.py`.
4. **F16 / R6:** Evaluate whether ping-pong traffic without DH epoch rotation meets your forward-secrecy bar; compare to Signal double-ratchet receive-side DH step.
5. Evaluate session rollback in `Session.decrypt_outer`.
6. File findings via [SECURITY.md](../../SECURITY.md) (private advisory).

## Exit criteria (P2-1)

- [x] Normative ratchet spec ([double-ratchet.md](../spec/double-ratchet.md))
- [x] Review package with question matrix (this document)
- [x] Deterministic test vector(s)
- [x] Adversarial regression tests
- [x] Internal self-review with documented open items
- [ ] Independent cryptographer sign-off or published third-party report

## References

- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-1, P2-5, P2-7
- [analysis-v1.md](./analysis-v1.md) §3 threat model
- `rust/yakr-core/src/ratchet.rs` — second implementation (interop, not audited)
