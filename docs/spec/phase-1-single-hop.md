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

### `GET /v1/blobs/{mailbox_tag}`

Return all non-expired blobs for the tag.

## Exit Criteria

- [x] Four CLI identities run in one test script without manual steps
- [x] Alice sends while Bob is offline; Bob fetches later
- [x] Relay stores ciphertext only (no plaintext sender/recipient IDs)
- [x] Expired blobs rejected on store and removed by sweeper
- [x] Duplicate `seq` detected client-side
- [x] README documents Docker demo in under 5 commands
