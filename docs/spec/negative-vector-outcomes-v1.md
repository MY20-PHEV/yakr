# Negative Vector Outcomes — v1.0

**Protocol:** `yakr-v1.0`  
**Status:** Normative (conformance)  
**Vectors:** `test-vectors-v1/negative/`  
**Verifier:** `interop_verifier.verify_negative_vector` (reference mapping only)

## Purpose

Negative vectors define **protocol-level rejection outcomes**. Independent implementations MUST reject the input and MUST NOT advance durable session or pairing state. They MUST NOT depend on matching Python exception text.

Each vector includes:

| Field | Required | Meaning |
|-------|----------|---------|
| `must_reject` | yes | Operation must fail (never return success) |
| `rejection_stage` | yes | Pipeline stage where rejection occurs |
| `normative_error_code` | yes | Stable identifier (this document) |
| `persistent_state_must_change` | yes | `false` for all v1.0 negative vectors |
| `retryable` | yes | `false` for all v1.0 negative vectors |
| `error_contains` | no | **Reference verifier hint only** — not required for third-party conformance |

## Rejection stages

| Stage | Description |
|-------|-------------|
| `pairing_validate` | Inviter validates joiner `PairingRequest` against invite |
| `pairing_request_decode` | CBOR decode of joiner request |
| `pairing_response_decode` | CBOR decode of inviter response |
| `invite_verify` | Ed25519 invite signature verification |
| `outer_blob_decode` | Relay JSON → outer blob structural validation |
| `ratchet_decrypt` | Ratchet header + AEAD decrypt |

## Normative error codes

| Code | Stage(s) | Meaning |
|------|----------|---------|
| `YAKR_E_PAIRING_UNEXPECTED_KEM` | `pairing_validate` | Classical invite received KEM ciphertext |
| `YAKR_E_PAIRING_MISSING_KEM` | `pairing_validate` | Hybrid invite missing required KEM ciphertext |
| `YAKR_E_PAIRING_INVITE_SECRET_MISMATCH` | `pairing_validate` | Joiner request invite secret ≠ invite |
| `YAKR_E_PAIRING_MISSING_JOINER_RATCHET` | `pairing_validate` | Joiner ratchet public key missing or wrong length |
| `YAKR_E_PAIRING_REQUEST_INVALID` | `pairing_request_decode` | Decoded CBOR is not a valid pairing request map |
| `YAKR_E_PAIRING_RESPONSE_INVALID` | `pairing_response_decode` | Decoded CBOR is not a valid pairing response map |
| `YAKR_E_CBOR_DECODE_FAILED` | `pairing_request_decode`, `pairing_response_decode` | CBOR parse failure |
| `YAKR_E_INVITE_SIGNATURE_INVALID` | `invite_verify` | Invite signature does not verify |
| `YAKR_E_OUTER_BLOB_INVALID_TAG` | `outer_blob_decode` | Mailbox tag not exactly 32 bytes after decode |
| `YAKR_E_OUTER_BLOB_MISSING_FIELD` | `outer_blob_decode` | Required relay JSON field absent |
| `YAKR_E_RATCHET_PAYLOAD_TOO_SHORT` | `ratchet_decrypt` | Ciphertext shorter than header minimum |
| `YAKR_E_RATCHET_INVALID_HEADER` | `ratchet_decrypt` | Magic or header layout invalid |
| `YAKR_E_RATCHET_DUPLICATE_MESSAGE` | `ratchet_decrypt` | Ratchet message number already consumed |
| `YAKR_E_RATCHET_SKIP_GAP` | `ratchet_decrypt` | Skip gap exceeds `MAX_SKIP_GAP` |
| `YAKR_E_RATCHET_AEAD_FAILED` | `ratchet_decrypt` | AEAD authentication failed (tampered ciphertext) |

## Conformance rules

1. Reject before committing pairing contacts, ratchet chains, or delivery sequence state.
2. Map internal errors to `normative_error_code` in test reports; substring matching is optional.
3. When `persistent_state_must_change` is `false`, ratchet root/chain counters and skipped-key tables MUST match pre-operation snapshots after rejection.
4. When `retryable` is `false`, the same bytes MUST NOT succeed on retry without new valid input.

## Reference verifier note

The Python `interop_verifier` infers `normative_error_code` from rejection behaviour and compares it to the vector. Third-party harnesses may assert codes directly without using `error_contains`.
