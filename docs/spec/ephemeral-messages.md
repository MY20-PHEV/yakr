# Ephemeral Messages — 24 Hour TTL

**Protocol:** `yakr-v1.0`  
**Status:** Implemented

## Policy (non-negotiable)

All chat text and delivery receipts expire **24 hours** after creation. This is not configurable per message or contact.

| Layer | Enforcement |
|-------|-------------|
| Inner message | `valid_until = created_at + 24h` |
| Relay blob | `expires_at ≤ now + 24h` (relay rejects longer) |
| Local SQLite | Encrypted inner bytes; sweeper deletes at `valid_until` |

Profiles and pairing artifacts use separate lifetimes.

## Inner message

Every `text` and `receipt` inner message includes:

```json
{
  "created_at": 1719835200000,
  "valid_until": 1719921600000,
  "seq": 42,
  "type": "text",
  "body": "…"
}
```

Clients **reject decrypt/display** when `now > valid_until` (`YAKR_ERR_MESSAGE_EXPIRED`).

## Local storage

- Plaintext bodies are **never** stored in SQLite.
- After the one-time ratchet decrypt on fetch, clients store `wrap_local_ciphertext(identity_key, inner.to_bytes())`.
- Listing or viewing messages unwraps locally and re-checks `valid_until`.
- `sweep_expired_messages()` runs on fetch and deletes expired rows.

## Relay

- `POST /v1/blobs` rejects `expires_at` more than 24 hours in the future.
- TTL sweeper deletes expired blobs (no consume-on-read).
- Undelivered messages disappear from relay after 24h; senders keep `outbound_pending` until delivery receipt or local expiry.

## Delivery receipts

Recipients send a delivery receipt after successfully decrypting text (single-hop and two-hop). Senders clear `outbound_pending` on receipt.

## Cryptography

Message payloads use the **X25519 double ratchet** — see [double-ratchet.md](./double-ratchet.md).

## Migration

Contacts without `ratchet.version == 2` must re-pair. Legacy symmetric ratchet (v0.4) is not interoperable.
