# Fetch Algorithm — Ordering, Receipts, and State

**Protocol:** `yakr-v1.0`  
**Status:** Normative (implemented in `yakr-cli`, `yakr-mobile`, `yakr-testkit`)

## Overview

Fetch polls mailbox relays for opaque blobs, decrypts them, persists ratchet state, and (for inbound `text`) sends delivery receipts. Relays **do not** consume blobs on read — the same ciphertext MAY appear on every poll until TTL expiry ([ephemeral-messages.md](./ephemeral-messages.md)).

Because multiple blobs can accumulate per tag and `GET /v1/blobs/{tag}` returns them in **arbitrary order** (typically by relay `stored_at`, which need not match application `seq`), clients MUST implement the algorithm below. A naive single-pass decrypt loop drops messages and receipts when a higher `seq` is processed before a lower one.

## Layers

| Layer | Ordering rule |
|-------|----------------|
| **Double ratchet** | MAY decrypt wire messages out of order via `skipped_keys` ([double-ratchet.md](./double-ratchet.md)) |
| **Application `seq`** | MUST be strictly monotonic per direction: only accept `inner.seq == last_recv_seq + 1` |

Receipts (`type: receipt`), `text`, `profile`, and `presence` messages all share one `seq` counter per sender on a contact (`next_send_seq` / `last_recv_seq`).

## Algorithm

For each mailbox tag in the fetch tag set (real epochs + decoys per privacy mode):

1. **Collect** blobs from direct hints (if any) and all configured relay URLs; deduplicate by `ciphertext`.
2. **Sort** the work queue by ascending `stored_at` (relay metadata). This is a hint only — correctness does not depend on relay order.
3. **Drain** the queue with a retry loop:
   - For each blob, call `Session.decrypt_outer`.
   - On `YAKR_ERR_DUPLICATE_SEQ` (duplicate or out-of-order `seq`, or ratchet replay): defer the blob to the next pass.
   - On other decrypt errors: drop the blob for this fetch.
   - On success with `inner.seq == last_recv_seq + 1`: handle by type (below), persist contact state, then continue.
   - Repeat until a full pass makes no progress.
4. **Flush** any queued outbound delivery receipts (`pending_receipts`) at the start of each contact fetch.

### `decrypt_outer` requirements

Implementations MUST:

- Reject `inner.seq <= last_recv_seq` as duplicate.
- Reject `inner.seq > last_recv_seq + 1` as out-of-order (map to `YAKR_ERR_DUPLICATE_SEQ` for the retry loop).
- **Rollback** ratchet receive state when rejecting after a successful ratchet decrypt, so deferred blobs can be retried later in the same fetch.

### Per message type

| `inner.type` | Action |
|--------------|--------|
| `text` | Save inbound row; send delivery receipt; persist contact |
| `receipt` | `mark_outbound_delivered(contact, message_id)`; persist contact |
| `profile` | Verify and merge `DeliveryProfile`; persist contact |
| `presence` | Apply presence update; persist contact |

### Delivery receipt send path

After decrypting inbound `text`, the recipient sends an encrypted `receipt` inner message referencing `message_id(outer.ciphertext)`.

**State rule:** `send_delivery_receipt` loads contact state, advances `next_send_seq`, and updates the send-side ratchet. The fetch loop MUST NOT overwrite that send-side state when saving receive-side updates. Implementations MUST merge send-side fields from disk (or send the receipt before the final `save_contact` for the inbound message) so each message gets a distinct receipt `seq`.

Receipts use the same single-hop mailbox failover path as sends. Failed receipt POSTs are queued in `pending_receipts` and retried via `yakr receipts flush` or the next fetch.

## Idempotency

- Second fetch on the same mailbox returns no new application messages when all blobs were already accepted (`DuplicateSeqError` on every blob).
- Relay blobs remain until TTL sweep; clients rely on `last_recv_seq`, not relay deletion.

## Exit criteria (tests)

- Burst send (N messages) → single fetch delivers all N in `seq` order.
- Delivery receipts: sender `outbound_pending` clears for all N after recipient fetch + sender fetch.
- Out-of-order relay `stored_at` does not drop messages or receipts ([mesh-testing-and-resilience.md](./mesh-testing-and-resilience.md)).

## Reference implementation

- `packages/yakr-cli/src/yakr_cli/fetch_cmds.py` — `fetch_contact_inbound`, `_refresh_contact_send_state`
- `packages/yakr-core/src/yakr_core/session.py` — `decrypt_outer`
- `packages/yakr-testkit/src/yakr_testkit/mesh_client.py` — test harness fetch loop
