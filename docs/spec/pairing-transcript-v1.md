# Pairing Transcript — Authenticated Key Agreement

**Protocol:** `yakr-v1.0`  
**Status:** Normative (ready for external review; see P2-1)  
**Related:** [yakr-protocol-v1.md](./yakr-protocol-v1.md), [offline-pairing.md](./offline-pairing.md), [phase-6-hybrid-pq.md](./phase-6-hybrid-pq.md)  
**Review:** [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md)

## Purpose

Pairing establishes the long-term `master_secret`, `contact_id`, initial ratchet state, and exchanged delivery profiles. This document specifies **exactly which bytes are hashed and mixed** so an external reviewer can answer:

- Are long-term identities bound to ephemeral keys?
- Can two parties derive the same secret while disagreeing about the peer?
- Are protocol versions and PQ negotiation included?
- Can messages be replayed across sessions?
- Do online rendezvous, offline QR, and in-process API paths agree on the cryptographic result?

Reference implementation: `packages/yakr-core/src/yakr_core/pairing.py`.

## Pairing state machine

```text
                    ┌─────────────────────────────────────────┐
                    │ ① InviteBundle (inviter → joiner)       │
                    │    verify_invite + safety code (voice)  │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │ ② PairingRequest (joiner → inviter)       │
                    │    build_pairing_request                  │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │ ③ PairingResponse (inviter → joiner)      │
                    │    inviter_complete_pairing               │
                    └──────────────────┬──────────────────────┘
                                       │
                    ┌──────────────────▼──────────────────────┐
                    │ ④ joiner_complete_pairing                 │
                    │    verify transcript_hash, derive master  │
                    └─────────────────────────────────────────┘
```

Steps ②–④ are **transport-independent**. The same CBOR objects and transcript are used whether messages travel over HTTP rendezvous, `yakr://` QR URLs, or direct in-process calls.

## Transport equivalence (normative)

| Transport | Invite | Request | Response | Cryptographic entry points |
|-----------|--------|---------|----------|---------------------------|
| Online rendezvous | `yakr://invite/…` or HTTP | POST to rendezvous | rendezvous poll / relay | `build_pairing_request` → `inviter_complete_pairing` → `joiner_complete_pairing` |
| Offline QR | `yakr://invite/…` (`rendezvous_hint = offline://qr`) | `yakr://pair-request/…` | `yakr://pair-response/…` | `build_offline_pairing_request` → `respond_to_pair_request` → `finish_offline_pairing` |
| Tests / mobile API | same invite object | in-memory `PairingRequest` | in-memory `PairingResponse` | `inviter_complete_pairing` / `joiner_complete_pairing` |

**Invariant:** For identical `InviteBundle`, `PairingRequest`, and inviter ephemeral public key, all transports MUST produce the same `transcript_hash` and `master_secret`.

**Not in transcript:** `rendezvous_hint`, `rendezvous_tls_spki_sha256`, transport framing, URL prefixes, and base64 encoding. These affect delivery routing or human verification only.

Verified by `test_pairing_path_equivalence.py` and `test_offline_pairing.py`.

## Wire encoding

### CBOR maps

Pairing messages are CBOR maps encoded with `cbor2.dumps`. Decoders MUST reject non-map top-level values with `ValueError` (or equivalent).

`PairingRequest` fields (reference order in `to_bytes`):

| Key | Type | Required |
|-----|------|----------|
| `invite_secret` | bytes(32) | yes |
| `joiner_name` | string | yes |
| `joiner_signing_public` | bytes(32) | yes |
| `joiner_agreement_public` | bytes(32) | yes |
| `joiner_ephemeral_public` | bytes(32) | yes |
| `joiner_profile` | bytes | no (default empty) |
| `kem_ciphertext` | bytes | hybrid only (ML-KEM-768 ciphertext) |

`PairingResponse` fields:

| Key | Type | Required |
|-----|------|----------|
| `inviter_ephemeral_public` | bytes(32) | yes |
| `transcript_hash` | bytes(32) | yes |
| `inviter_profile` | bytes | no (default empty) |

### URL wrappers (offline / QR)

| Prefix | Payload |
|--------|---------|
| `yakr://pair-request/` | URL-safe base64 (no padding) of `PairingRequest.to_bytes()` |
| `yakr://pair-response/` | URL-safe base64 (no padding) of `PairingResponse.to_bytes()` |

Round-trip: `pair_request_to_url` / `pair_request_from_url` and `pair_response_to_url` / `pair_response_from_url`. URL encoding is **not** authenticated; only the decoded CBOR participates in the transcript.

## Participants and messages

| Message | Direction | Transport |
|---------|-----------|-----------|
| `InviteBundle` | Inviter → Joiner | QR / URL / relay rendezvous |
| `PairingRequest` | Joiner → Inviter | QR / relay |
| `PairingResponse` | Inviter → Joiner | QR / relay |

All long-term public keys are Ed25519 (signing) and X25519 (agreement). Ephemeral X25519 keys are fresh per pairing attempt.

## InviteBundle (authenticated by inviter)

Signed CBOR fields (see `yakr-protocol-v1.md` §5.1). Relevant to transcript:

- `protocol` (UTF-8 string, e.g. `yakr-v0.4` or `yakr-v0.6`)
- `signing_public` (inviter)
- `agreement_public` (inviter)
- `invite_secret` (32 random bytes)
- `kem_public` when hybrid PQ enabled (`capabilities` contains `hybrid_pq`)
- optional `rendezvous_hint`, `rendezvous_tls_spki_sha256` (signed but **not** in transcript)

Joiner MUST verify inviter signature (`verify_invite`) before proceeding.

## PairingRequest (joiner → inviter)

See §Wire encoding. Inviter MUST reject if `invite_secret` mismatch (`validate_pairing_request_for_invite`).

## PairingResponse (inviter → joiner)

See §Wire encoding. Joiner MUST reject if `transcript_hash` does not recompute from local copy of invite + request + `inviter_ephemeral_public`.

## Validation order (normative)

### Joiner (before sending request)

1. `verify_invite(invite)`
2. `build_pairing_request` — generates ephemeral key; encapsulates ML-KEM if hybrid

### Inviter (on request)

1. `verify_invite(invite)` (if not already verified)
2. `validate_pairing_request_for_invite(invite, request)` — secret match, PQ policy
3. Generate or reuse inviter ephemeral X25519 keypair
4. `transcript_hash = pairing_transcript(invite, request, inviter_ephemeral_public)`
5. Decapsulate `kem_ciphertext` if hybrid; `derive_pair_master`
6. Verify `joiner_profile` signature if present
7. Emit `PairingResponse` with `transcript_hash`

### Joiner (on response)

1. Decode `PairingResponse` (from URL or bytes)
2. Recompute `pairing_transcript(invite, request, response.inviter_ephemeral_public)` — **reject on mismatch**
3. `validate_pairing_request_for_invite` (defence in depth)
4. `derive_pair_master_joiner` with joiner-held `pq_secret` if hybrid
5. Verify `inviter_profile` signature if present

## Transcript hash (normative)

Let `parts` be an ordered list of **raw byte strings** (no length prefixes):

```text
parts = [
    UTF8(invite.protocol),
    invite.invite_secret,              // 32 bytes
    invite.signing_public,             // 32 bytes
    invite.agreement_public,           // 32 bytes
    request.joiner_signing_public,     // 32 bytes
    request.joiner_agreement_public,   // 32 bytes
    request.joiner_ephemeral_public,   // 32 bytes
    inviter_ephemeral_public,          // 32 bytes
]
if invite_supports_hybrid(invite):
    parts.append(request.kem_ciphertext)   // ML-KEM-768 ciphertext (1088 bytes)

transcript_hash = SHA-256( parts[0] || b"|" || parts[1] || b"|" || ... || parts[n-1] )
```

Delimiter is ASCII `|` (0x7C) between fields. There is **no** delimiter before the first field or after the last.

`invite_supports_hybrid(invite)` is true when `hybrid_pq` is in `invite.capabilities` and `invite.kem_public` is non-empty.

### Worked example (classical)

Vector `classical-pairing-v1` in [pairing_transcript.json](./test-vectors-v1/pairing_transcript.json):

- `invite.protocol` = `yakr-v0.4` (8 bytes)
- Eight identity/ephemeral public fields as fixed hex in the vector
- No `kem_ciphertext` field
- Expected `transcript_hash` = `c67e196c…f5992`

### Worked example (hybrid)

Vector `hybrid-pairing-v1` in the same file adds `kem_ciphertext` as the ninth hashed field when `invite.protocol` = `yakr-v0.6`.

Hybrid master derivation vectors (isolated HKDF step) remain in [hybrid_kex.json](./test-vectors-v1/hybrid_kex.json).

Hybrid invites MUST include non-empty `kem_ciphertext` in the request; classical invites MUST NOT include `kem_ciphertext` (enforced by `validate_pairing_request_for_invite`).

### What is bound

| Property | Bound? | Mechanism |
|----------|--------|-----------|
| Inviter long-term identity | Yes | `invite.signing_public`, `invite.agreement_public` in hash |
| Joiner long-term identity | Yes | `joiner_signing_public`, `joiner_agreement_public` in hash |
| Ephemeral contributions | Yes | Both ephemeral public keys in hash |
| Invite freshness | Partial | `invite_secret` uniqueness per invite |
| PQ negotiation | Yes (hybrid) | `kem_ciphertext` appended when hybrid |
| Protocol version string | Yes | `invite.protocol` as first transcript field |
| Delivery profiles | **Out of band** | Profiles verified by signature after derive; not in transcript hash |
| Rendezvous relay identity | Partial | `rendezvous_tls_spki_sha256` in signed invite only |

## PQ downgrade policy (normative)

| Case | Behaviour |
|------|-----------|
| Hybrid invite, empty `kem_ciphertext` | **Reject** before transcript hash |
| Classical invite, non-empty `kem_ciphertext` | **Reject** before transcript hash |
| Hybrid invite, valid `kem_ciphertext` | Include in transcript; use hybrid master derivation |

Implemented in `validate_pairing_request_for_invite`; tested in `test_pairing_pq_downgrade.py`.

## Master secret derivation (normative)

### Classical path

```text
identity_shared   = X25519(inviter_agreement_private, joiner_agreement_public)
                    = X25519(joiner_agreement_private, inviter_agreement_public)
ephemeral_shared  = X25519(inviter_ephemeral_private, joiner_ephemeral_public)
                    = X25519(joiner_ephemeral_private, inviter_ephemeral_public)

master_secret = HKDF-SHA256(
    ikm = identity_shared || ephemeral_shared,
    salt = transcript_hash,
    info = b"yakr/v0.4/pair-master",
    length = 32,
)
```

### Hybrid PQ path

When `invite_supports_hybrid(invite)` and `kem_ciphertext` is present:

```text
pq_secret = KEM_decapsulate(inviter_kem_secret, kem_ciphertext)   // inviter
          = joiner-held secret from KEM_encapsulate(invite.kem_public)

x_secret = identity_shared || ephemeral_shared
master_secret = HKDF-SHA256(
    ikm = x_secret || pq_secret,
    salt = transcript_hash,
    info = b"yakr/v0.6/hybrid-master",
    length = 32,
)
```

See `hybrid_pq.py` for ML-KEM-768 sizes and `derive_hybrid_master`.

## Derived contact state

After `master_secret`:

| Field | Derivation |
|-------|------------|
| `conversation_id` | `pairwise_{sorted_names}` — lexical sort of display names, e.g. `pairwise_alice_bob` |
| `contact_id` | `SHA-256(signing_public \|\| agreement_public)` per peer (32 bytes) |
| `transcript_hash` | stored on `Contact` |
| `ratchet` | `RatchetState.from_master(master_secret, hybrid=…)` |

`conversation_id` is a local display/session grouping key, not a global identifier. Distinct pairings with the same display names but different long-term keys produce different `contact_id` and `master_secret`.

## Profile handling post-pairing

Delivery profiles in `PairingRequest` / `PairingResponse` are **signed by the sender's long-term signing key** and verified with `verify_delivery_profile` before storage.

### v1.0 design decision: profiles not in transcript

Profiles are **not** included in `transcript_hash`. This is an explicit v1.0 choice (not an oversight):

1. Long-term signing keys are already bound in the transcript; profile signatures are verified under those keys immediately after pairing.
2. Profiles are versioned and rotated post-pairing under [profile-replay-policy.md](./profile-replay-policy.md).
3. Keeping profiles out of the transcript avoids re-pairing when relay URLs or capability generations change.

**Residual risk:** A malicious peer could substitute a different signed profile at pairing time if the victim does not inspect profile contents (relay URLs, TLS pins). Mitigations: human safety-code verification at invite step, profile inspection in client UI, and profile replay policy on updates.

**Future:** v1.1 MAY add optional `profile_digest` fields to the transcript; absent that extension, implementations MUST NOT silently bind profiles in the hash.

## Security properties (claimed / to prove)

| Property | Status |
|----------|--------|
| MITM without breaking invite or ephemeral DH | Intended — requires review |
| Unknown key-share (different peer view) | Intended — identities in transcript |
| Replay pairing across sessions | New `invite_secret` per attempt |
| Downgrade PQ → classical only | **Rejected** — `validate_pairing_request_for_invite` |
| Cross-protocol replay | Mitigated — `invite.protocol` bound in transcript |
| Transport path divergence | **Rejected** — same CBOR → same transcript (tested) |

## Open gaps (tracked)

| ID | Gap | Status |
|----|-----|--------|
| G1 | ~~`protocol` not in transcript hash~~ | **Closed** |
| G2 | ~~PQ downgrade if inviter strips KEM after hybrid invite~~ | **Closed** |
| G3 | Profile bytes not in transcript | **Closed** — v1.0 design decision (§Profile handling) |
| G4 | Online vs offline pairing path byte identity | **Closed** — transport equivalence tests |
| G5 | Independent cryptographer review | Open — P2-1 |

## Review checklist (for external auditor)

1. Confirm transcript field order matches `pairing_transcript()` in reference code.
2. Confirm HKDF labels and salt match §Master secret derivation.
3. Evaluate unknown key-share with swapped ephemeral keys.
4. Evaluate invite replay windows and `invite_secret` entropy.
5. Evaluate hybrid downgrade when `kem_ciphertext` empty on hybrid invite.
6. Confirm `conversation_id` / `contact_id` semantics for your threat model.
7. Confirm profile-out-of-transcript decision is acceptable for deployment.
8. Recompute vectors in [pairing_transcript.json](./test-vectors-v1/pairing_transcript.json) independently.

## Exit criteria

- [x] Cross-language test vectors: classical + hybrid → `transcript_hash` + `master_secret` ([pairing_transcript.json](./test-vectors-v1/pairing_transcript.json))
- [x] Documented PQ downgrade policy implemented
- [x] Transport equivalence documented and tested
- [x] Profile binding decision documented with rationale
- [ ] External review sign-off or documented findings (P2-1)

## References

- `packages/yakr-core/src/yakr_core/pairing.py` — `pairing_transcript`, `derive_pair_master`, URL helpers
- `packages/yakr-testkit/tests/test_pairing_transcript.py` — vector conformance
- `packages/yakr-testkit/tests/test_pairing_path_equivalence.py` — transport invariance
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-2, P2-3, P2-4
