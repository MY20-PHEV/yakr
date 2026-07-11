# Operator Identity vs Relay Client Capability (P1-3)

**Protocol:** `yakr-v1.1`  
**Status:** Normative  
**Related:** [ADR 012](../adr/012-relay-capability-tokens.md), [relay-capability-v1.md](./relay-capability-v1.md), [homelab-relay.md](../homelab-relay.md)

## Purpose

Homelab operators run **three distinct cryptographic roles**. Conflating them weakens privacy (stable `contact_id` on the wire) and complicates compromise recovery.

## Three keys (normative)

| Role | Key material | Stored where | Used for |
|------|--------------|--------------|----------|
| **Messaging identity** | Owner Ed25519 signing key (`alice`) | Owner `YAKR_HOME` | E2E pairing, profile signatures, message envelopes |
| **Relay operator identity** | Separate Ed25519 key (`alice-ops`) | `relays/<name>/identity.json` | Operator delivery profile, TLS cert subject, pairing with owner |
| **Capability issuance key** | Ed25519 (`relay-issuance/issuance.key`) | `relays/<name>/relay-issuance/` | Signs `CapabilityGrant`; advertised via `/healthz` |

### MUST / MUST NOT

1. **MUST** use a dedicated operator identity name distinct from the owner (`alice` ≠ `alice-ops`).
2. **MUST NOT** send the owner's long-term `signing_public` or global `contact_id` on capability-authenticated `POST /v1/blobs` or `POST /v1/fetch`.
3. **MUST** use relay-signed capability grants as the trust anchor for capability mode (not client self-sign).
4. **MAY** use `RelayTicket` with `contact_id` only during capability bootstrap (`/v1/capabilities/issue`) or legacy ticket mode.

## Wire exposure by auth mode

| Artifact | Ticket mode | Capability mode |
|----------|-------------|-----------------|
| Owner `signing_public` | In ticket (`issuer_signing_public`) | **Not sent** |
| Global `contact_id` | In ticket | **Not sent** |
| Operator TLS SPKI pin | In profile descriptor | In profile descriptor |
| `capability_id` | N/A | Per-relay pseudonym (rotates with generation + salt) |
| `auth_public` | N/A | Ephemeral request-signing key bound in grant |

## Compromise response

| Compromised material | Impact | Recovery |
|---------------------|--------|----------|
| Owner messaging key | Full E2E for paired contacts | New identity + re-pair |
| Operator identity key | Forged operator profiles / TLS identity | Rotate operator bundle (`yakr relay create --force`), redeploy TLS, `profile publish` |
| Capability issuance key | Forged grants until detected | Rotate `relay-issuance/`, redeploy relay, `profile publish` to bump capability generation |
| Single capability grant | Relay access scoped to grant permissions | `profile publish` (auto-revokes prior id) or operator revoke endpoint |

## Manifest documentation

`relays/<operator>/manifest.json` records issuance key fingerprint for operators:

| Field | Description |
|-------|-------------|
| `capability_issuance_public_b64` | Raw Ed25519 public key bytes (base64) |
| `capability_issuance_public_sha256` | SHA-256 hex fingerprint for deploy verification |

Peers learn the live issuance key from `GET /healthz` → `capability_issuance_public` and verify grants against it.

## References

- [relay-observer-privacy-v1.md](./relay-observer-privacy-v1.md) — what relays can correlate
- [tls-pin-lifecycle.md](./tls-pin-lifecycle.md) — TLS pin rotation
- `packages/yakr-core/src/yakr_core/relay_operator.py` — bundle layout
