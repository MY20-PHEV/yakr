# Double Ratchet — X25519 DH

**Protocol:** `yakr-v1.0`  
**Status:** Implemented — **experimental; not externally audited** (see [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-7)

## Overview

Pairwise sessions use a **double ratchet**: symmetric message-key chains plus X25519 DH steps when the peer advertises a new ratchet public key in the message header.

This replaces the v0.4 symmetric-only ratchet (`yakr/v0.4/ratchet-send`).

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

## Bootstrap (pairing)

From pairwise `master_secret`:

```text
root_key    = HKDF(master, "yakr/v1.0/double-ratchet-root")
send_chain  = HKDF(root, "yakr/v1.0/double-ratchet-send")
recv_chain  = HKDF(root, "yakr/v1.0/double-ratchet-recv")
```

Initiator keeps `(send, recv)`. Joiner swaps chains. Each side generates an X25519 ratchet key pair.

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

Lexicographically smaller contact name is the ratchet initiator when using `Contact.establish` (tests and `contact-add`). Invite pairing uses inviter/joiner roles.
