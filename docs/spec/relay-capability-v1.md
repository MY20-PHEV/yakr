# Relay Capability v1 — Authorization Wire Format

**Protocol:** `yakr-v1.1` (proposed)  
**Status:** Draft — design per [ADR 012](../adr/012-relay-capability-tokens.md)  
**Replaces (eventually):** stable `contact_id` in [relay tickets](../../packages/yakr-core/src/yakr_core/relay_ticket.py)  
**Review:** [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md)

## Overview

A **relay capability** is a short-lived, relay-scoped authorization proving the holder may perform `post`, `fetch`, or `presence` operations against a specific relay descriptor. Relays verify the capability without learning the holder's global pairing `contact_id` or long-term operator signing key.

**v1.1 requires a trust anchor.** A self-signed capability blob is insufficient (see §Trust anchor).

## Trust anchor (normative)

Verification MUST establish that **this relay authorised this capability holder**, not merely that a signature is internally consistent.

### CapabilityGrant (relay-signed)

Issued during operator pairing registration or profile-driven capability publish:

```cbor
{
  "protocol": "yakr-relay-capability-grant-v1",
  "capability_id": <bytes, 16>,
  "capability_generation": <uint>,
  "relay_name": <tstr>,
  "relay_tls_spki_sha256": <bytes, 32>,
  "permissions": [<tstr>, ...],
  "expires_at": <uint, ms since epoch>,
  "auth_public": <bytes, 32>,
  "relay_signature": <bytes>
}
```

`relay_signature` = Ed25519-Sign(`relay_signing_private`, unsigned_grant_bytes).

The relay signing key is the operator's relay identity key (distinct from user messaging identity). It MAY be the TLS key if policy allows; prefer a dedicated relay issuance key.

### Request proof (client-signed)

Each authorized HTTP request includes headers (exact names TBD in relay API spec):

| Header | Value |
|--------|-------|
| `Yakr-Capability-Grant` | base64 CBOR `CapabilityGrant` |
| `Yakr-Capability-Timestamp` | ms since epoch |
| `Yakr-Capability-Nonce` | random 16 bytes, base64 |
| `Yakr-Capability-Signature` | Ed25519-Sign(`auth_private`, signing_input) |

```text
signing_input = method || "\n" || path || "\n" || body_sha256 || "\n" || timestamp || "\n" || nonce
```

### Relay verification (normative)

1. `CapabilityGrant.protocol` matches.
2. `expires_at > now` (grant) and timestamp within ±5 minutes.
3. `relay_name` and `relay_tls_spki_sha256` match this relay.
4. Requested operation ∈ `permissions`.
5. `relay_signature` verifies under this relay's issuance public key.
6. `auth_public` is **registered and active** for this grant (relay store).
7. `capability_generation` is the current active generation (or grant matches stored record).
8. `Yakr-Capability-Signature` verifies under `auth_public` over `signing_input`.
9. Nonce not replayed within TTL window.

**Rule 6 is mandatory.** Rules 5–8 without registration allow arbitrary attacker minted grants if the relay does not verify its own signature origin.

### Alternative: bearer MAC (Option A)

Homelab relays MAY implement a simpler model:

- relay issues random `(capability_id, capability_secret)` at pairing;
- client sends `MAC(capability_secret, signing_input)`;
- no `auth_public` layer.

This MUST NOT be mixed with self-signed Ed25519 grants on the same endpoint without explicit capability mode negotiation.

## Client key derivation

After registration, the client holds `auth_private` / `auth_public`. Keys MAY be derived:

```text
capability_seed = HKDF(
    master_secret,
    info = b"yakr-relay-capability-v1"
        || relay_name
        || relay_tls_spki_sha256
        || capability_generation
        || issuance_salt,
)
capability_id = HKDF(capability_seed, info=b"id", length=16)
auth_seed     = HKDF(capability_seed, info=b"auth", length=32)
auth_keypair  = Ed25519.from_seed(auth_seed)
```

| Field | Source |
|-------|--------|
| `capability_generation` | Monotonic; bumped on intentional rotation |
| `issuance_salt` | Random 16 bytes at registration; carried in signed `RelayDescriptor` (`capability_issuance_salt`) |

**Deterministic derivation without `capability_generation` or `issuance_salt` MUST NOT be used** — it produces stable `capability_id` across rotations (weakens unlinkability).

## Rotation

To rotate:

1. Client increments `capability_generation`, generates new `issuance_salt`, and publishes them in the delivery profile (`yakr profile publish`).
2. Client derives new `capability_id` and `auth_keypair`.
3. Client obtains new `CapabilityGrant` from relay via `POST /v1/capabilities/issue` (no manual bootstrap when relay advertises issuance key).
4. Relay marks previous generation revoked after overlap window (default 1h).

Expired grants are rejected; revoked generations are rejected even if signature still verifies.

## Relationship to RelayTicket v1

| Aspect | RelayTicket v1 | RelayCapability v1.1 |
|--------|----------------|----------------------|
| Stable contact link | `contact_id` | None |
| Operator identity | `issuer_signing_public` | Hidden |
| Trust anchor | Inviter long-term signing key | **Relay issuance signature + registration** |
| Relay binding | `relay_name` | `relay_name` + TLS SPKI pin |
| TTL default | 1h | 24h max |

During migration, relays accept `Authorization: RelayTicket <b64>` **or** capability grant headers.

## Implementation status

| Component | Status |
|-----------|--------|
| Spec + ADR (trust anchor) | Draft |
| `yakr-core` issue/verify + `capability_client` | **Partial** — issue, register, request headers |
| `yakr-relay` grant store + POST auth + `POST /v1/fetch` | **Partial** |
| Operator pairing bootstrap | **Partial** — `yakr relay capability-bootstrap`, pairing hook |
| Client profile publish | Not started |

Track in [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1, P1-2.

## References

- [ADR 012](../adr/012-relay-capability-tokens.md)
- [relay-authorization.md](./relay-authorization.md)
- [tls-endpoints.md](./tls-endpoints.md)
- [profile-replay-policy.md](./profile-replay-policy.md)
