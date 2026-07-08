# Phase 2 — Two-Hop Onion Relay

**Protocol:** `yakr-v0.2`  
**Status:** Implemented (wire format); **not used by reference client v1**

The reference CLI and testkit default to **single-hop** `POST /v1/blobs` delivery
with ordered mailbox failover. Two-hop onion packets remain in the spec and
test vectors for optional metadata-hardening deployments; see
[relay-failover.md](./relay-failover.md).

## Goal

No single honest relay observes both sender upload and recipient fetch for the same message.

## Wire Format

Phase 2 uses CBOR for onion packet layers. The client posts a base64url packet to the entry relay:

### `POST /v1/relay` (entry)

```json
{
  "packet": "<base64url cbor>"
}
```

Entry relay decrypts its layer and forwards to the mailbox relay ingest endpoint.

### `POST /v1/ingest` (mailbox)

```json
{
  "inner": "<base64url encrypted mailbox layer>"
}
```

Mailbox relay decrypts and stores the opaque blob via the Phase 1 blob store.

## Receipts

Delivery receipts are encrypted inner messages of type `receipt`. In **two-hop**
deployments the recipient MAY return them over the reversed route
(`mailbox,entry`). The **reference client** uses the same single-hop mailbox
failover path as sends ([relay-failover.md](./relay-failover.md)).

Each inbound `text` message MUST produce a distinct receipt `seq`. Fetch implementations MUST follow [fetch-algorithm.md](./fetch-algorithm.md) so send-side ratchet state is not overwritten when persisting receive-side state.

## Exit Criteria

- [x] Entry relay forwards without storing mailbox tags
- [x] Mailbox relay stores without seeing the original sender
- [x] Sender receives delivery receipt after recipient fetch
- [x] CBOR onion packets round-trip in testkit golden tests
- [x] Docker demo for two-hop delivery
