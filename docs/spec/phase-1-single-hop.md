# Phase 1 — Single-Hop Offline Delivery

**Protocol:** `yakr-v0.1`  
**Status:** Implemented

## Goal

Alice delivers an encrypted message to offline Bob through one mailbox relay without a central message server.

## Crypto Profile — Classical v1

| Purpose | Primitive |
|---------|-----------|
| Identity signing | Ed25519 |
| Key agreement | X25519 |
| KDF | HKDF-SHA256 |
| Message AEAD | XChaCha20-Poly1305 |
| Mailbox tag | HMAC-SHA256 |

Domain separation:

```text
yakr/v0.1/master
yakr/v0.1/message-key
yakr/v0.1/mailbox-tag
```

## Relay API

### `POST /v1/blobs`

Store an opaque blob.

```json
{
  "mailbox_tag": "<base64url>",
  "expires_at": 1719835200000,
  "ciphertext": "<base64url>"
}
```

Validation:

- `mailbox_tag` must decode to 32 bytes
- `expires_at` must be in the future
- `ciphertext` ≤ 64 KiB

### `GET /v1/blobs/{mailbox_tag}` (legacy)

Returns all non-expired blobs for the tag. **Deprecated for new clients** — mailbox tags in URL paths leak to infra logs. Use `POST /v1/fetch` instead.

### `POST /v1/fetch` (preferred)

```json
{
  "mailbox_tags": ["<base64url>", "..."],
  "ticket": "<optional relay ticket>"
}
```

Returns merged blob list for all tags. When `require_capabilities` is enabled on the relay, clients MUST authorize with capability headers (`fetch` permission) instead of a ticket.

Return all non-expired blobs for the tag. Order is implementation-defined (`stored_at` ascending is typical); clients MUST NOT assume blob order matches application `seq` ([fetch-algorithm.md](./fetch-algorithm.md)).

Relay blobs MUST expire within **24 hours** — see [ephemeral-messages.md](./ephemeral-messages.md).

## Exit Criteria

- [x] Four CLI identities run in one test script without manual steps
- [x] Alice sends while Bob is offline; Bob fetches later
- [x] Relay stores ciphertext only (no plaintext sender/recipient IDs)
- [x] Expired blobs rejected on store and removed by sweeper
- [x] Duplicate `seq` detected client-side (strict `last_recv_seq + 1`; out-of-order blobs retried per [fetch-algorithm.md](./fetch-algorithm.md))
- [x] README documents Docker demo in under 5 commands

See also [mesh-testing-and-resilience.md](./mesh-testing-and-resilience.md) for Charlie 3-peer stress tests and relay outage findings.
