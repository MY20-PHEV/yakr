# Yakr Protocol v1.0

**Status:** Normative  
**Date:** 2026-07-07  
**Protocol identifier:** `yakr-v1.0`

This document freezes the Yakr reference protocol as an implementable open standard. It consolidates phases 1–8 (`yakr-v0.1` through `yakr-v0.7`) into a single versioned profile suitable for independent client interop.

## 1. Scope

Yakr provides decentralised, end-to-end encrypted messaging through a social relay network. Peers need not be online simultaneously; opaque ciphertext blobs are stored at mailbox relays and fetched later.

Implementations MUST support:

- Classical identity and session establishment (Ed25519 / X25519)
- Single-hop and multi-hop relay delivery
- Invite-based pairing and relay tickets
- Signed delivery profiles
- Optional hybrid post-quantum key agreement (ML-KEM-768)
- Metadata-hardening privacy modes (decoy tags, relay delay)

Mobile clients (Phase 8) are a reference profile, not a wire-format requirement.

## 2. Versioning and Extensions

### 2.1 Protocol version strings

| String | Meaning |
|--------|---------|
| `yakr-v0.1` | Classical single-hop wire format |
| `yakr-v0.4` | Invite bundles |
| `yakr-v0.5` | Delivery profiles |
| `yakr-v0.6` | Hybrid PQ pairing |
| `yakr-v0.7` | Privacy metadata extensions |
| `yakr-v1.0` | Frozen interop baseline (this document) |

A `yakr-v1.0` implementation MUST accept all prior wire objects where noted below and MUST NOT emit deprecated fields.

### 2.2 Extension rules

1. **CBOR maps** (invites, profiles, relay packets): unknown keys MUST be ignored on decode unless marked critical in a future spec.
2. **Inner messages** (JSON): unknown keys MUST be ignored; `version` MUST be checked.
3. **Capabilities** (invite `capabilities` array): clients MUST ignore unknown capability strings.
4. **New protocol strings** require a new minor or major document revision; do not overload existing strings.
5. **PQ rekey**: hybrid sessions MUST rekey after 10,000 messages or 7 days (see §6.3).

## 3. Cryptographic Profile

### 3.1 Primitives

| Purpose | Primitive |
|---------|-----------|
| Identity signing | Ed25519 |
| Key agreement | X25519 |
| Post-quantum KEM | ML-KEM-768 (`pqcrypto` / NIST FIPS 203) |
| Post-quantum signing (invites) | ML-DSA-65 |
| KDF | HKDF-SHA256 |
| Message AEAD | XChaCha20-Poly1305 (24-byte nonce prepended) |
| Mailbox tag | HMAC-SHA256 |
| Invite safety code | SHA-256 → decimal digit groups |

### 3.2 Domain separation (HKDF `info` / salt)

```text
yakr/v0.1/master
yakr/v0.1/message-key
yakr/v0.1/mailbox-tag
yakr/v0.4/pair-master
yakr/v0.4/ratchet-send
yakr/v0.4/ratchet-recv
yakr/v0.6/hybrid-master
yakr/v0.7/relay-delay
```

### 3.3 Master secret (classical pairing)

```text
master = HKDF-SHA256(
  ikm  = X25519_shared,
  salt = transcript_hash,
  info = "yakr/v0.1/master" | "yakr/v0.4/pair-master"  # per pairing version
)
```

### 3.4 Hybrid master (v0.6+)

```text
x_secret = identity_shared || ephemeral_shared
master   = HKDF-SHA256(
  ikm  = x_secret || pq_secret,   # pq_secret is ML-KEM shared secret (32 bytes)
  salt = transcript_hash,
  info = "yakr/v0.6/hybrid-master"
)
```

### 3.5 Message keys

```text
message_key(seq) = HKDF-SHA256(
  ikm  = master_secret,
  salt = "",
  info = "yakr/v0.1/message-key" || BE_u64(seq)
)
```

### 3.6 Mailbox secret and tag

```text
mailbox_secret = HKDF-SHA256(
  ikm  = master_secret,
  salt = "",
  info = "yakr/v0.1/mailbox-tag" || UTF8(direction)
)

tag = HMAC-SHA256(
  key = mailbox_secret,
  msg = UTF8(direction) || "|" || UTF8(decimal(epoch))
)
```

`epoch = floor(unix_seconds / epoch_secs)`. Default `epoch_secs = 3600`; delivery profiles MAY override.

`direction` is a stable pairwise string, e.g. `alice->bob` (sender → recipient).

## 4. Wire Objects

### 4.1 Inner message (JSON, UTF-8)

```json
{
  "version": 1,
  "conversation_id": "pairwise_alice_bob",
  "sender_device_id": "abc123",
  "seq": 1,
  "created_at": 1700000000000,
  "type": "text",
  "body": "hello",
  "message_id": null
}
```

Types: `text`, `receipt`, `profile`. Keys are sorted lexicographically on encode.

Plaintext is encrypted with XChaCha20-Poly1305 under `message_key(seq)`. Ciphertext format: `nonce(24) || ciphertext+tag`.

### 4.2 Outer blob

```text
OuterBlob {
  version: u8 = 1
  mailbox_tag: bytes32
  expires_at: unix_ms
  ciphertext: bytes    # encrypted inner message or onion layer
}
```

### 4.3 Invite bundle (CBOR)

Required keys: `protocol`, `inviter_name`, `signing_public`, `agreement_public`, `invite_secret`, `rendezvous_hint`, `expires_at`, `capabilities`, `signature`.

Hybrid invites (`yakr-v0.6`) add `kem_public`, `pq_signing_public`, `pq_signature`.

Signature covers the CBOR map **without** `signature` / `pq_signature` keys.

Invite URL: `yakr://invite/<base64url(cbor)>`.

**Safety code** (out-of-band verification):

```text
digest = SHA256(signing_public || agreement_public)
digits = concat(str(byte % 10) for byte in digest[0:10])
display = "{digits[0:4]} {digits[4:8]} {digits[8:10]}"
```

### 4.4 Delivery profile (CBOR)

Protocol `yakr-v0.5`. Signed fields: `protocol`, `version`, `valid_from`, `valid_until`, `direct_hints`, `relay_descriptors`, `mailbox_params`, `blob_classes`, `receipt_policy`.

`relay_descriptors[]`: `{name, role, url, wrap_secret}` where `wrap_secret` is 32 raw bytes.

### 4.5 Relay HTTP API

Base path `/v1`.

| Method | Path | Body | Response |
|--------|------|------|----------|
| GET | `/healthz` | — | `{"status":"ok"}` |
| POST | `/v1/blobs` | `{mailbox_tag, expires_at, ciphertext, ticket?}` | 201 |
| GET | `/v1/blobs/{mailbox_tag}` | — | `[{...}]` |
| POST | `/v1/relay` | `{packet, ticket?}` | 202 (entry relay) |
| POST | `/v1/ingest` | `{inner, ticket?}` | 201 (mailbox relay) |

All binary fields are **base64url** without padding.

**Relay validation (normative):**

| Check | Action |
|-------|--------|
| `mailbox_tag` decodes to exactly 32 bytes | 400 if not |
| `expires_at` > now (ms) | 400 if not |
| `len(ciphertext)` ≤ 65536 | 400 if not |
| Blobs per tag ≤ `max_blobs_per_tag` (default 256) | 429 if exceeded |
| Valid relay ticket when `require_tickets` | 401 if missing/invalid |

Relays MUST NOT decrypt application plaintext.

## 5. Session Flow (summary)

1. **Invite** — inviter publishes signed `InviteBundle`; joiner verifies signature and safety code.
2. **Pairing** — X25519 (+ optional ML-KEM) → `master_secret`, ratchet state.
3. **Profile exchange** — signed `DeliveryProfile` selects relays, epoch, receipt policy.
4. **Send** — encrypt inner message, wrap in `OuterBlob`, optionally onion-route through entry → mailbox relay.
5. **Fetch** — derive mailbox tags for current and lookback epochs, GET blobs, decrypt.

Detailed phase specs remain in `docs/spec/phase-*.md`.

## 6. Post-Quantum and Privacy

### 6.1 Hybrid capability

Invite `capabilities` MUST include `hybrid_pq` for PQ pairing. Joiner encapsulates against `kem_public`; both sides derive §3.4 master.

### 6.2 PQ rekey

Implementations MUST rekey hybrid sessions when `messages_sent ≥ 10_000` OR `session_age ≥ 7 days`. Error: `YAKR_ERR_PQ_REKEY_REQUIRED`.

### 6.3 Privacy modes (v0.7)

- **Decoy mailbox tags** — HMAC with synthetic `decoy|{direction}|{epoch}|{index}` material.
- **Relay delay** — entry relays MAY sleep `uniform(0, forward_delay_max_secs)` before forward.

## 7. Error Model

Structured errors (string constants):

```text
YAKR_ERR_RELAY_OFFLINE
YAKR_ERR_RELAY_UNAUTHORIZED
YAKR_ERR_BLOB_EXPIRED
YAKR_ERR_DECRYPT_FAILED
YAKR_ERR_PROFILE_STALE
YAKR_ERR_ROUTE_EXHAUSTED
YAKR_ERR_INVITE_EXPIRED
YAKR_ERR_PQ_REKEY_REQUIRED
```

## 8. Test Vectors

Canonical vectors live in `docs/spec/test-vectors-v1/`:

| File | Verifies |
|------|----------|
| `hybrid_kex.json` | §3.4 hybrid master derivation |
| `invite.json` | Invite CBOR + Ed25519 signature + safety code |
| `delivery_profile.json` | Profile CBOR + Ed25519 signature |
| `mailbox_tag.json` | §3.6 mailbox tag |
| `inner_message.json` | §4.1 JSON canonical form |

Independent implementations MUST pass the interop verifier suite (see `interop/README.md`) using only this document and the vector files.

## 9. Security Considerations

See `docs/security/analysis-v1.md` for threat model, trust assumptions, and mitigations.

## 10. References

- Phase specs: `docs/spec/phase-1-single-hop.md` … `phase-8-mobile.md`
- PQ library decision: `docs/adr/006-pq-library.md`
- Glossary: `docs/spec/glossary.md`
