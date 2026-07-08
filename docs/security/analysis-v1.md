# Yakr Security Analysis v1.0

**Status:** Reviewed against `yakr-v1.0` threat model  
**Date:** 2026-07-07

## 1. Threat Model

### 1.1 Assets

- Message plaintext and metadata (conversation ID, sequence numbers, timing)
- Long-term identity keys (Ed25519, X25519, optional ML-DSA / ML-KEM)
- Session master secrets and ratchet state
- Delivery profiles and relay routing hints

### 1.2 Adversaries

| Adversary | Capability |
|-----------|------------|
| Network observer | Passive traffic analysis on relay links |
| Malicious relay | Stores, drops, replays, or rate-limits blobs; learns mailbox tags and blob sizes |
| Compromised contact relay | Same as malicious relay but within user's trust circle |
| Offline ciphertext collector | Archives blobs for future cryptanalysis |
| Quantum adversary (future) | Breaks classical DH/ECDH; harvest-now-decrypt-later |

### 1.3 Out of scope

- Endpoint compromise (malware on device)
- Physical device seizure without passphrase (mobile store mitigates at rest)
- Global traffic correlation across all relays (partial mitigation via decoy tags)
- Sybil flood against rendezvous (rendezvous is hint-only in v1)

## 2. Trust Assumptions

1. Users manually verify invite **safety codes** out of band.
2. Users choose relays they trust (friends); protocol does not prove relay honesty.
3. Relays are **untrusted for confidentiality** — they handle only opaque ciphertext.
4. Delivery profiles may only list relays operated by **paired contacts** (or self). See `docs/spec/relay-authorization.md`.
5. PQ hybrid mode assumes ML-KEM-768 and ML-DSA-65 remain secure.

## 3. Cryptographic Properties

| Property | Mechanism | Notes |
|----------|-----------|-------|
| Confidentiality | XChaCha20-Poly1305 | Per-message keys from HKDF(master, seq) |
| Authenticity | AEAD + signed invites/profiles | Ed25519 / ML-DSA for artifacts |
| Forward secrecy (pairing) | Ephemeral X25519 in pairing | Ratchet extends for ongoing messages |
| PQ confidentiality | ML-KEM-768 hybrid master | Combined with classical DH |
| Mailbox unlinkability (weak) | HMAC tags rotate per epoch | Observer sees tag changes hourly by default |

## 4. Relay Abuse

### 4.1 Threat

A client or external actor floods a relay with blobs to exhaust storage or deny service to a mailbox tag.

### 4.2 Mitigations (reference relay)

| Control | Default | Effect |
|---------|---------|--------|
| Max blob size | 64 KiB | Bounds per-request memory |
| Tag length | 32 bytes | Prevents ambiguous decode |
| Expiry enforcement | `expires_at > now` | Rejects dead-on-arrival blobs |
| Per-tag blob cap | 256 | Returns HTTP 429 when exceeded |
| Ticket auth (optional) | `require_tickets` | Limits store to paired users |

### 4.3 Residual risk

Global rate limiting per IP is deployment-specific and not mandated in v1. Operators SHOULD add reverse-proxy limits.

## 5. Metadata Hardening (v0.7)

- **Decoy tags** — fetch pattern includes dummy tags; reduces confidence of traffic analysis but does not hide volume.
- **Relay delay** — randomises forward timing; mitigates coarse timing correlation.

## 6. Mobile At-Rest (Phase 8)

`MobileStore` wraps SQLite + file state with passphrase-derived Fernet keys. Passphrase loss is irrecoverable by design.

## 7. Known Limitations

1. **Receipts** leak delivery confirmation timing to relays (minimal receipt policy reduces content).
2. **Profile staleness** — clients must refresh signed profiles; stale profile error is intentional.
3. **No MLS-style group messaging** in v1 — pairwise sessions only.
4. **Classical-only invites** remain vulnerable to future quantum break of recorded pairing transcripts; use hybrid invites when PQ libraries are available.

## 8. Review Checklist

- [x] Threat model states relay as honest-but-curious at best
- [x] PQ upgrade path documented (hybrid + rekey policy)
- [x] Abuse limits specified in protocol §4.5 and implemented in reference relay
- [x] Error codes map to explicit failure modes
- [x] Versioning rules prevent silent downgrade (protocol string checks on invites/profiles)

## 9. Recommendations for Deployments

1. Enable `require_tickets` on public relays.
2. Run mailbox sweep (`sweep_expired`) on an interval.
3. Prefer hybrid PQ pairing for long-lived relationships.
4. Pin relay TLS certificates where possible (transport layer, outside this spec). **Implemented:** `endpoint_tls_spki_sha256` in signed delivery profiles; see `docs/spec/tls-endpoints.md`.
