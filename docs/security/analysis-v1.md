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
| Confidentiality | XChaCha20-Poly1305 | Per-message keys from double ratchet (see [session-ratchet-review-v1.md](session-ratchet-review-v1.md)) |
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
5. **Presence metadata** — encrypted `type=presence` inner messages reduce exposure, but relays still observe poll timing, blob sizes, and which mailbox tags are requested. Fresh presence URLs in the cache are advisory; clients fall back to signed profile `relay_descriptors` when presence expires. Embedded relays MUST only set `relay.active=true` when a dialable `reachable` URL is verified (ADR 008).
6. **Platform wake metadata** (optional, ADR 011) — opt-in wake registration exposes device tokens to trusted relays and the wake gateway; wake timing is more precise than poll-only. No message plaintext leaves the relay blob path. Apple/Google process silent push per their policies.
7. **Ratchet persistence** — send/receive atomic commits land in SQLite (`atomic_commit_send`, `atomic_commit_receive_text`); delivery receipts are queued in the same receive transaction and flushed on the next fetch if POST fails.
8. **Relay-visible tickets** — optional `require_tickets` exposes `issuer_signing_public` and `contact_id` to relays; per-relay pseudonymous capabilities are planned (P1-1).

## 8. Presence and Relay Reachability (Phase 10)

### 8.1 Threat

A network or relay observer may learn:

- When a client polls (`GET /v1/blobs/{tag}`)
- Which relay URLs are contacted (including group relays from the trust graph)
- Approximate poll frequency (mitigated by privacy modes and decoy tags)

Presence payloads carried as E2E inner messages protect **operator location hints** from relay plaintext inspection, but a curious relay still sees **when** polls happen after presence-driven URL changes.

### 8.2 Mitigations

| Control | Effect |
|---------|--------|
| Short presence TTL (30 min) | Limits stale route abuse window |
| Signed profile fallback | Wrap secrets cannot change via presence alone |
| Pairing-gated relay advertisement | Random relays cannot be injected without profile update |
| `relay_active=false` when not dialable | Prevents false embedded-relay advertisements on NAT/cellular |
| Trust-graph poll set | `yakr fetch --all` polls authorized relays only (profiles + cached presence from paired operators) |
| Decoy mailbox tags (Balanced/High) | Reduces tag correlation confidence |

### 8.3 Residual risk

Presence does not provide anonymity against a global observer correlating poll times across relays. High-risk users should combine relay placement, Tor transport (future), and operational discipline.

### 8.4 Optional platform wake (ADR 011)

Users who **opt in** to platform wake delegate a wake capability to relays they already trust for blob storage. A wake gateway and the platform provider (APNs/FCM) see device handles and wake timing, not ciphertext. Users who need minimum third-party metadata SHOULD leave wake disabled and rely on poll-only delivery.

### 8.5 Relay-observer privacy

Normative table: **[relay-observer-privacy-v1.md](../spec/relay-observer-privacy-v1.md)**.

Summary for the default **single-hop mailbox** path:

| Observation | Mailbox relay | Network observer | Wake gateway (opt-in) |
|-------------|---------------|------------------|------------------------|
| Poster / fetcher IP | Yes | TLS metadata only | N/A |
| Mailbox tag | Yes | No (inside TLS) | No |
| Blob size | Yes | Approximate | No |
| Plaintext / identity keys | **No** | **No** | **No** |
| Ticket `contact_id` | Yes (legacy ticket mode) | No | No |
| `capability_id` | Yes (capability mode) | No | No |
| Timing / volume | Yes | Yes | Wake timing |

**Wording standard:** say *relays do not receive plaintext identifiers or decrypt contents* — not *relays never know who sent or fetched* (network and operator context may deanonymise). See the normative spec for two-hop entry/mailbox split and auth-mode columns.

## 9. Review Checklist

- [x] Threat model states relay as honest-but-curious at best
- [x] PQ upgrade path documented (hybrid + rekey policy)
- [x] Abuse limits specified in protocol §4.5 and implemented in reference relay
- [x] Error codes map to explicit failure modes
- [x] Versioning rules prevent silent downgrade (protocol string checks on invites/profiles)

## 10. Recommendations for Deployments

1. Enable **`--require-capabilities`** on friend-operator relays (homelab default); use tickets only for capability bootstrap.
2. Run mailbox sweep (`sweep_expired`) on an interval.
3. Prefer hybrid PQ pairing for long-lived relationships.
4. Pin relay TLS certificates where possible (transport layer, outside this spec). **Implemented:** `endpoint_tls_spki_sha256` in signed delivery profiles; see `docs/spec/tls-endpoints.md`.
