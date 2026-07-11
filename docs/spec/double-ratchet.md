# Double Ratchet — X25519 DH

**Protocol:** `yakr-v1.0`  
**Status:** Implemented — **experimental; not externally audited** (see [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-7, [session-ratchet-review-v1.md](../security/session-ratchet-review-v1.md) P2-1)

> **F16 (resolved 2026-07-11):** Option B (pairing-time DH init). Active DH ratchet applies on the **normative invite-pairing path** only. See [Session bootstrap paths](#session-bootstrap-paths-normative) and [external-ratchet-review-f16-issue-2-2026-07-11.md](../reviews/external-ratchet-review-f16-issue-2-2026-07-11.md).

## Overview

Pairwise sessions on the **invite-pairing path** use a **double ratchet**: symmetric message-key chains plus X25519 DH steps when the peer advertises a new ratchet public key in the message header.

The wire format (`YKDR2`) is shared with other bootstrap paths, but only invite pairing runs the asymmetric init that activates DH epochs in normal traffic. Do not describe all of v1.0 as “Double Ratchet” without that qualifier — see [Session bootstrap paths](#session-bootstrap-paths-normative).

This replaces the v0.4 symmetric-only ratchet (`yakr/v0.4/ratchet-send`).

## Session bootstrap paths (normative)

| Path | API / entry | Transcript-bound | DH ratchet in normal traffic | Role |
|------|-------------|------------------|------------------------------|------|
| **Invite pairing** | `build_pairing_request` → `inviter_complete_pairing` → `joiner_complete_pairing` | Yes — [pairing-transcript-v1.md](./pairing-transcript-v1.md) | **Yes** (Option B) | **Normative production bootstrap** |
| **Manual establish** | `Contact.establish()` | No — pre-shared public bundles only | **No** — symmetric chains only | **Non-normative** — tests, mesh fixtures, `contact-add`, local dev |

Production clients MUST create contacts through invite pairing. `Contact.establish()` is a compatibility helper: it derives the same `master_secret` shape from long-term keys but does **not** exchange ratchet public keys in a transcript and does **not** run pairing-time DH init. Future work is either to migrate `establish` to the same asymmetric bootstrap or to deprecate it in favour of pairing-only production paths ([SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-8).

## State (`ratchet.version == 2`)

Persisted on each `Contact`:

| Field | Purpose |
|-------|---------|
| `root_key` | DH ratchet root |
| `dh_self_private` / `dh_self_public` | Our current ratchet key pair |
| `dh_peer_public` | Peer's ratchet public from last header |
| `send_chain_key` / `recv_chain_key` | Symmetric chains |
| `send_n` / `recv_n` | Message counters |
| `prev_send_n` | Previous chain length (header) |
| `skipped_keys` | Out-of-order message keys |

## Skipped-key bounds (normative)

To limit DoS via huge forward `message_n` gaps:

| Constant | Default | Behaviour |
|----------|---------|-----------|
| `MAX_SKIP_GAP` | 128 | Reject decrypt when `message_n - recv_n` exceeds this |
| `MAX_SKIPPED_KEYS` | 256 | Reject when storing more skipped chain keys would exceed this |

Implementations MUST clear `skipped_keys` on DH ratchet step (new peer public key).

Violations surface as decrypt failure (`DecryptError` at session layer).

## Bootstrap (pairing)

From pairwise `master_secret`:

```text
root_key    = HKDF(master, "yakr/v1.0/double-ratchet-root")
send_chain  = HKDF(root, "yakr/v1.0/double-ratchet-send")
recv_chain  = HKDF(root, "yakr/v1.0/double-ratchet-recv")
```

Initiator keeps `(send, recv)`. Joiner swaps chains. Each side generates an X25519 ratchet key pair (joiner in `PairingRequest`; inviter in `PairingResponse`).

## Pairing-time DH init (Option B)

After `from_master`, pairing completes asymmetric ratchet bootstrap so the first encrypted traffic can rotate DH epochs without breaking send-before-receive mesh delivery:

| Role | At `complete_pairing` | On first `encrypt` |
|------|----------------------|-------------------|
| **Inviter** | Store `pending_pairing_dh_ratchet_peer = joiner_ratchet_public`; keep bootstrap `recv_chain` | `_pairing_send_init(joiner_ratchet_public)` — rotate `dh_self_public`, derive **send** chain only |
| **Joiner** | `_pairing_recv_init(inviter_ratchet_public)` — set `dh_peer_public`, derive **recv** chain from `DH(joiner_priv, inviter_pub)`; keep bootstrap `send_chain` | unchanged |

First inviter ciphertext advertises the **post-init** `dh_self_public` (not the transcript `inviter_ratchet_public`). Joiner performs a normal pre-decrypt `_dh_ratchet` when the header key differs from stored `dh_peer_public`.

Joiner may send before receiving inviter traffic (bootstrap send chain, pairing `joiner_ratchet_public` in header). Inviter decrypts with bootstrap `recv_chain` until it has received joiner traffic.

See [Session bootstrap paths](#session-bootstrap-paths-normative) for `Contact.establish()` behaviour.

## Wire envelope

Prepended to each encrypted payload inside `OuterBlob.ciphertext`:

```text
YKDR2 | dh_public(32) | prev_n(u32 BE) | message_n(u32 BE) | XChaCha ciphertext
```

AAD binds header bytes to the ciphertext.

## Per-message keys

```text
message_key, chain_key = HKDF-Expand(chain_key, "yakr/v1.0/double-ratchet-ck")
```

## DH ratchet step

When `dh_public` in the header differs from stored `dh_peer_public` (after the first message):

1. `RK, recv_chain = KDF-RK(root, DH(self_priv, peer_pub))`
2. Generate new self key pair
3. `RK, send_chain = KDF-RK(root, DH(new_self_priv, peer_pub))`
4. Reset `send_n` / `recv_n`

Domain labels:

```text
yakr/v1.0/double-ratchet-rk   # root step
yakr/v1.0/double-ratchet-ck   # chain step
```

## Replay

Re-decrypting the same `(dh_public, message_n)` raises duplicate detection; `Session` maps this to `YAKR_ERR_DUPLICATE_SEQ`.

## Application `seq` vs ratchet order

The ratchet MAY decrypt a future wire message before earlier ones (using `skipped_keys`). Application logic MUST still accept only `inner.seq == last_recv_seq + 1`. If the ratchet decrypt succeeds but `seq` is not next, implementations MUST roll back receive ratchet state and surface `YAKR_ERR_DUPLICATE_SEQ` so the fetch loop can retry after lower `seq` blobs. See [fetch-algorithm.md](./fetch-algorithm.md).

## Initiator rule

| Bootstrap path | Initiator |
|----------------|-----------|
| Invite pairing | **Inviter** (pairing response side) |
| `Contact.establish` | Lexicographically smaller contact **display name** (non-normative; tests and `contact-add` only) |
