# ADR 012: Per-Relay Capability Tokens

**Status:** Accepted (design) — **amended** 2026-07-10 (trust anchor + rotation)  
**Date:** 2026-07-10  
**Implements:** [relay-capability-v1.md](../spec/relay-capability-v1.md)  
**Review:** [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md)

## Context

`RelayTicket` (v1) embeds:

- `issuer_signing_public` — long-term operator identity
- `contact_id` — stable pseudonym derived from the pairing

Friend-operator relays learn both on every `POST`/`GET` authorization. External review flagged this as **P1 identity privacy**: a relay that serves multiple contacts can correlate traffic to a stable `contact_id` and operator key.

Goals for v1.1 capability layer:

1. **Unlinkability** — different relays see different capability identifiers for the same contact.
2. **Scoped permissions** — `post`, `fetch`, `presence` per relay descriptor.
3. **Rotation** — capabilities expire and can be re-issued without changing pairing keys.
4. **Backward compatibility** — v1 `RelayTicket` remains valid during migration.

### Authorisation gap (amendment)

An early draft let clients self-sign capabilities with an ephemeral `auth_public`. That proves **internal consistency only** — any attacker can mint a valid-looking capability. **P1 implementation is blocked** until a normative trust anchor is defined ([relay-capability-v1.md](../spec/relay-capability-v1.md) §Trust anchor).

## Decision

Introduce **`RelayCapability`** (CBOR) as the successor authorization object. Relays verify capabilities without learning global `contact_id`.

| Field (v1 ticket) | v1.1 capability |
|-------------------|-----------------|
| `contact_id` | `capability_id` (per-relay opaque, 16 bytes) |
| `issuer_signing_public` | hidden — `auth_public` registered at issuance |
| `relay_name` | `relay_name` + `relay_tls_spki_sha256` pin |
| `permissions` | `permissions` (unchanged semantics) |
| `expires_at` | `expires_at` (shorter default: 24h) |

### Trust anchor: relay-signed registration (Option B + C)

Capabilities use a **two-layer** model:

1. **Registration (relay-issued)** — During operator pairing or profile-driven registration, the relay signs a `CapabilityGrant` binding:
   - `capability_id`
   - `auth_public` (client Ed25519 key for request signing)
   - `permissions`
   - `expires_at`
   - `capability_generation` (monotonic uint for rotation)
   - relay identity (`relay_name`, `relay_tls_spki_sha256`)

2. **Request (client-signed)** — Each HTTP request carries:
   - the `CapabilityGrant` (or reference + cached copy)
   - `request_signature` = Ed25519-Sign(`auth_private`, `method || path || body_hash || timestamp || nonce`)

The relay verifies:

- grant signature is from **this relay's operator TLS identity key** (or dedicated relay signing key);
- `auth_public` in the grant matches the request signer;
- grant is registered and not revoked;
- `capability_generation` is the highest active generation for that `capability_id` prefix (or exact match);
- timestamp/nonce within skew window.

**Self-signed client capabilities alone MUST NOT be accepted.**

Alternative **relay-issued bearer MAC** (Option A) remains valid for homelab relays that prefer simplicity; v1.1 reference MAY implement B first.

### Derivation and rotation

Client `auth_keypair` MAY be derived from pairing material, but **`capability_id` and generation MUST NOT be purely deterministic from `(master_secret, relay_descriptor)` alone** — that would produce stable relay-visible pseudonyms across rotations.

Normative derivation:

```text
capability_seed = HKDF(
    master_secret,
    info = b"yakr-relay-capability-v1"
        || relay_name
        || relay_tls_spki_sha256
        || capability_generation
        || issuance_salt,
)
capability_id   = HKDF(capability_seed, info=b"id", length=16)
auth_keypair    = Ed25519.from_seed(HKDF(capability_seed, info=b"auth", length=32))
```

| Input | Purpose |
|-------|---------|
| `capability_generation` | Monotonic counter in profile publish; bump to rotate |
| `issuance_salt` | Random 16 bytes chosen at registration; carried in encrypted profile update |

**Trade-off (explicit):** deterministic recovery without `issuance_salt` is convenient for backup restore; unlinkable rotation requires changing `capability_generation` and/or `issuance_salt`. v1.1 defaults to **rotation over determinism**.

### Migration

| Phase | Behaviour |
|-------|-----------|
| v1.0 (now) | `RelayTicket` with `contact_id` |
| v1.1 | Relays accept **either** ticket or registered capability |
| v1.2 | Capabilities required; tickets deprecated |

Reference implementation keeps `relay_ticket.py` until v1.1 relay + client work lands ([SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1).

## Consequences

**Positive**

- Relay observers cannot correlate the same contact across relays via stable `contact_id`.
- Compromised capability rotates without re-pairing (bump generation).
- Trust anchor is explicit — no self-sign ambiguity.

**Negative**

- Registration step during pairing or profile publish.
- Relay must store active grants (or verify grant chain on each request).
- More complex client profile publish.

## Alternatives considered

1. **Client self-signed capability only** — rejected (authorisation gap).
2. **Hash contact_id per relay** — rejected for unlinkability.
3. **Pure deterministic HKDF without generation/salt** — rejected; stable `capability_id` weakens rotation ([follow-up critique](../reviews/github-follow-up-critique-2026-07-10.md)).

## References

- [relay-capability-v1.md](../spec/relay-capability-v1.md)
- [relay_ticket.py](../../packages/yakr-core/src/yakr_core/relay_ticket.py)
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1, P1-2
