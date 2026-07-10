# ADR 012: Per-Relay Capability Tokens

**Status:** Accepted (design)  
**Date:** 2026-07-10  
**Implements:** [relay-capability-v1.md](../spec/relay-capability-v1.md)

## Context

`RelayTicket` (v1) embeds:

- `issuer_signing_public` — long-term operator identity
- `contact_id` — stable pseudonym derived from the pairing

Friend-operator relays learn both on every `POST`/`GET` authorization. External review ([external-critique-2026-07-10.md](../reviews/external-critique-2026-07-10.md)) flagged this as **P1 identity privacy**: a relay that serves multiple contacts can correlate traffic to a stable `contact_id` and operator key.

Goals for v1.1 capability layer:

1. **Unlinkability** — different relays see different capability identifiers for the same contact.
2. **Scoped permissions** — `post`, `fetch`, `presence` per relay descriptor.
3. **Rotation** — capabilities expire and can be re-issued without changing pairing keys.
4. **Backward compatibility** — v1 `RelayTicket` remains valid during migration.

## Decision

Introduce **`RelayCapability`** (CBOR, Ed25519-signed) as the successor authorization object. Clients derive relay-specific capabilities from pairing material; relays verify capabilities without learning global `contact_id`.

| Field (v1 ticket) | v1.1 capability |
|-------------------|-----------------|
| `contact_id` | `capability_id` (per-relay random, 16 bytes) |
| `issuer_signing_public` | `auth_public` (ephemeral Ed25519, per capability) |
| `relay_name` | `relay_name` + `relay_tls_spki_sha256` pin |
| `permissions` | `permissions` (unchanged semantics) |
| `expires_at` | `expires_at` (shorter default: 24h) |

### Derivation (normative sketch)

```
capability_seed = HKDF(
    master_secret,
    info = b"yakr-relay-capability-v1" || relay_name || relay_tls_spki_sha256,
)
capability_id = HKDF(capability_seed, info=b"id", length=16)
auth_keypair = Ed25519.from_seed(HKDF(capability_seed, info=b"auth", length=32))
```

The operator signs the capability with `auth_private`, not the long-term identity key. Relays store an allow-list of active `capability_id` values (or verify signature + expiry only).

### Migration

| Phase | Behaviour |
|-------|-----------|
| v1.0 (now) | `RelayTicket` with `contact_id` |
| v1.1 | Relays accept **either** ticket or capability |
| v1.2 | Capabilities required; tickets deprecated |

Reference implementation keeps `relay_ticket.py` until v1.1 relay + client work lands ([SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1).

## Consequences

**Positive**

- Relay observers cannot correlate the same contact across relays via stable `contact_id`.
- Compromised relay credential rotates without re-pairing.

**Negative**

- More complex client profile publish (one capability per relay descriptor).
- Relay operators must implement new verification path.

## Alternatives considered

1. **Hash contact_id per relay** — simpler but still derived from stable input; rejected for unlinkability.
2. **Anonymous credentials (MAC)** — heavier crypto; deferred.
3. **No change** — rejected; privacy table commitment in [analysis-v1.md](../security/analysis-v1.md).

## References

- [relay-capability-v1.md](../spec/relay-capability-v1.md)
- [relay_ticket.py](../../packages/yakr-core/src/yakr_core/relay_ticket.py)
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P1-1, P1-2
