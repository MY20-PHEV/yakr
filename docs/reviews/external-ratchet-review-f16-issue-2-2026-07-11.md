# External Review — F16 / R6 (DH Ratchet Inactive in Normal Traffic)

**Date:** 2026-07-11  
**Source:** [GitHub issue #2](https://github.com/MY20-PHEV/yakr/issues/2)  
**Protocol:** `yakr-v1.0`  
**Related:** Discussion [#1](https://github.com/MY20-PHEV/yakr/discussions/1), [ratchet-self-review-2026-07-11.md](./ratchet-self-review-2026-07-11.md), [session-ratchet-review-v1.md](../security/session-ratchet-review-v1.md)

## Verdict

| Item | Assessment |
|------|------------|
| F16 validity | **Confirmed** — genuine design issue |
| Exploit demonstrated | **No** |
| Impact class | Design-level; affects future-message recovery after compromise, not current PCS claims (PCS explicitly out of scope for v1.0) |
| Spec naming | Current behaviour is **inconsistent** with ordinary “Double Ratchet” expectations |

## Reviewer analysis (summary)

The reviewer walked `RatchetState` initialisation, `encrypt()`, `decrypt()`, and `_dh_ratchet()`:

1. Symmetric send/recv chains advance per message and may protect **past** messages when prior chain state is erased.
2. Normal traffic provides **no trigger** for either peer to change advertised `dh_public`.
3. First `decrypt()` records peer key without root transition; DH processing requires a **later** header with a **different** peer public key.
4. Since sends continue advertising the same local key, ping-pong stays on **pairing-derived symmetric chains only**.
5. The X25519 ratchet is **inactive**, not merely infrequent.

### Wording correction (accepted)

Prefer:

> Normal sessions advance only the pairing-derived symmetric chains. The X25519 ratchet keys exchanged in message headers do not contribute to the root key unless a peer independently changes its advertised public key.

This is closer to an **inactive DH ratchet** than a long-lived active DH epoch.

## Caution on naive fix

**Do not** simply call `_dh_ratchet(peer_public)` on the first-message branch:

- The first inbound ciphertext was encrypted under the bootstrap symmetric chain; replacing `recv_chain_key` before authentication would break decryption.
- Post-decrypt transition needs analysis for **simultaneous initial sends** (both sides could diverge from different DH inputs).

The reviewer classifies this as an **initialisation problem**, not a one-line `decrypt()` patch.

## Recommended resolution paths

### Option A — Deliberate symmetric-only v1.0

Rename/describe v1.0 accurately as a **bidirectional symmetric-key ratchet** with per-message key evolution. Defer DH / post-compromise recovery to a later protocol revision. Reduces complexity; avoids claiming Double Ratchet semantics the live protocol does not provide.

### Option B — Real double ratchet at pairing time

Use inviter/joiner asymmetry during pairing to establish initial DH-ratchet state:

1. One role contributes an initial ratchet public key in pairing.
2. The other generates its ratchet key and performs the initial DH operation.
3. First encrypted message carries the new public key.
4. Receiver performs the normal receive-side DH transition.
5. Each received peer ratchet key drives the next local key.

Architecturally cleaner than arbitrary periodic rotation; may require pairing transcript or protocol-version change.

**Reviewer preference:** Resolve ambiguity explicitly — Option A or Option B, not silent status quo.

## Maintainer response

| Action | Status |
|--------|--------|
| Save review in `docs/reviews/` | Done (this file) |
| Update review package wording | Done |
| Protocol change | **Option B implemented** (pairing transcript + asymmetric ratchet init) |
| Close F16 | **Closed** (pairing path, issue #2). `Contact.establish` classified non-normative in spec |

## Tracking

- Issue: https://github.com/MY20-PHEV/yakr/issues/2
- Discussion: https://github.com/MY20-PHEV/yakr/discussions/1
- Backlog: P2-1 partial; **F16 closed** (pairing path); P2-8 tracks `Contact.establish` future
