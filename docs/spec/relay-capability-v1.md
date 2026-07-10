# Relay Capability v1 — Authorization Wire Format

**Protocol:** `yakr-v1.1` (proposed)  
**Status:** Draft — design per [ADR 012](../adr/012-relay-capability-tokens.md)  
**Replaces (eventually):** stable `contact_id` in [relay tickets](../../packages/yakr-core/src/yakr_core/relay_ticket.py)

## Overview

A **relay capability** is a short-lived, relay-scoped authorization proving the holder may perform `post`, `fetch`, or `presence` operations against a specific relay descriptor. Relays verify the capability without learning the holder's global pairing `contact_id` or long-term operator signing key.

## CBOR object

```cbor
{
  "protocol": "yakr-relay-capability-v1",
  "capability_id": <bytes, 16>,
  "relay_name": <tstr>,
  "relay_tls_spki_sha256": <bytes, 32>,
  "permissions": [<tstr>, ...],
  "expires_at": <uint, ms since epoch>,
  "auth_public": <bytes, 32>,
  "signature": <bytes, 64>
}
```

### Unsigned payload (signed bytes)

All fields except `signature`, CBOR-encoded in canonical order:

| Field | Type | Notes |
|-------|------|-------|
| `protocol` | string | MUST be `yakr-relay-capability-v1` |
| `capability_id` | bytes(16) | Relay-opaque pseudonym |
| `relay_name` | string | Must match descriptor in delivery profile |
| `relay_tls_spki_sha256` | bytes(32) | Pin from `RelayDescriptor` |
| `permissions` | array of string | Subset of `post`, `fetch`, `presence` |
| `expires_at` | uint | MUST be ≤ now + 24h at issue |
| `auth_public` | bytes(32) | Ed25519 public key used for signature |

`signature` = Ed25519-Sign(`auth_private`, unsigned_payload).

## Verification (relay)

1. `protocol` matches.
2. `expires_at > now`.
3. `relay_name` and `relay_tls_spki_sha256` match this relay's configured identity.
4. Requested operation ∈ `permissions`.
5. Ed25519 verify `auth_public` over unsigned payload.

Relays MUST NOT log `capability_id` alongside long-term identity fields — it is already pseudonymous per relay.

## Client issuance

Capabilities are derived from pairing `master_secret` and the target `RelayDescriptor` (see ADR 012 HKDF labels). Clients attach capabilities to:

- `POST /v1/blobs` — `post`
- `GET /v1/blobs/{tag}` — `fetch`
- Presence publish endpoints — `presence`

Profile publish includes freshly minted capabilities for each advertised relay (or references to cached capability blobs with sufficient TTL).

## Relationship to RelayTicket v1

| Aspect | RelayTicket v1 | RelayCapability v1.1 |
|--------|----------------|----------------------|
| Stable contact link | `contact_id` | None |
| Operator identity | `issuer_signing_public` | Hidden (`auth_public` only) |
| Relay binding | `relay_name` | `relay_name` + TLS SPKI pin |
| TTL default | 1h | 24h max |

During migration, relays accept `Authorization: RelayTicket <b64>` **or** `Authorization: RelayCapability <b64>`.

## Security notes

- Compromise of one capability does not reveal `master_secret` if derivation uses HKDF with per-relay salt.
- Revocation: wait for `expires_at` or operator block-list of `capability_id` (optional relay policy).
- Replay of expired capability: rejected by expiry check.

## Implementation status

| Component | Status |
|-----------|--------|
| Spec + ADR | Draft |
| `yakr-core` issue/verify | Not started |
| `yakr-relay` middleware | Not started |
| Client profile publish | Not started |

Track in [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1, P1-2.

## References

- [ADR 012](../adr/012-relay-capability-tokens.md)
- [delivery_profile.py](../../packages/yakr-core/src/yakr_core/delivery_profile.py) — `RelayDescriptor`
- [tls-endpoints.md](./tls-endpoints.md)
