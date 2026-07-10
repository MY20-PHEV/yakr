# Pairing Transcript — Authenticated Key Agreement

**Protocol:** `yakr-v1.0`  
**Status:** Normative draft (P2 — cryptographer review target)  
**Related:** [yakr-protocol-v1.md](./yakr-protocol-v1.md), [offline-pairing.md](./offline-pairing.md), [phase-6-hybrid-pq.md](./phase-6-hybrid-pq.md)  
**Review:** [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md)

## Purpose

Pairing establishes the long-term `master_secret`, `contact_id`, initial ratchet state, and exchanged delivery profiles. This document specifies **exactly which bytes are hashed and mixed** so an external reviewer can answer:

- Are long-term identities bound to ephemeral keys?
- Can two parties derive the same secret while disagreeing about the peer?
- Are protocol versions and PQ negotiation included?
- Can messages be replayed across sessions?

Reference implementation: `packages/yakr-core/src/yakr_core/pairing.py`.

## Participants and messages

| Message | Direction | Transport |
|---------|-----------|-----------|
| `InviteBundle` | Inviter → Joiner | QR / URL / relay rendezvous |
| `PairingRequest` | Joiner → Inviter | QR / relay |
| `PairingResponse` | Inviter → Joiner | QR / relay |

All long-term public keys are Ed25519 (signing) and X25519 (agreement). Ephemeral X25519 keys are fresh per pairing attempt.

## InviteBundle (authenticated by inviter)

Signed CBOR fields (see `yakr-protocol-v1.md` §5.1). Relevant to transcript:

- `signing_public` (inviter)
- `agreement_public` (inviter)
- `invite_secret` (32 random bytes)
- `protocol_version` / hybrid KEM fields when PQ enabled
- optional `rendezvous_hint`, `rendezvous_tls_spki_sha256`

Joiner MUST verify inviter signature before proceeding.

## PairingRequest (joiner → inviter)

CBOR map (canonical field order in implementation):

| Field | Type | Notes |
|-------|------|-------|
| `invite_secret` | bytes(32) | MUST match invite |
| `joiner_name` | string | Display name |
| `joiner_signing_public` | bytes(32) | Ed25519 |
| `joiner_agreement_public` | bytes(32) | X25519 |
| `joiner_ephemeral_public` | bytes(32) | X25519 ephemeral |
| `joiner_profile` | bytes | Signed `DeliveryProfile` CBOR (optional) |
| `kem_ciphertext` | bytes | Present when hybrid PQ invite |

Inviter MUST reject if `invite_secret` mismatch.

## PairingResponse (inviter → joiner)

| Field | Type | Notes |
|-------|------|-------|
| `inviter_ephemeral_public` | bytes(32) | X25519 ephemeral |
| `transcript_hash` | bytes(32) | See §Transcript hash |
| `inviter_profile` | bytes | Signed delivery profile (optional) |

Joiner MUST reject if `transcript_hash` does not recompute.

## Transcript hash (normative)

```text
parts = [
    invite.invite_secret,
    invite.signing_public,
    invite.agreement_public,
    request.joiner_signing_public,
    request.joiner_agreement_public,
    request.joiner_ephemeral_public,
    inviter_ephemeral_public,
]
if request.kem_ciphertext is non-empty:
    parts.append(request.kem_ciphertext)

transcript_hash = SHA-256( parts[0] || b"|" || parts[1] || b"|" || ... || parts[n-1] )
```

Delimiter is ASCII `|` (0x7C) between **raw byte fields** in list order.

### What is bound

| Property | Bound? | Mechanism |
|----------|--------|-----------|
| Inviter long-term identity | Yes | `invite.signing_public`, `invite.agreement_public` in hash |
| Joiner long-term identity | Yes | `joiner_signing_public`, `joiner_agreement_public` in hash |
| Ephemeral contributions | Yes | Both ephemeral public keys in hash |
| Invite freshness | Partial | `invite_secret` uniqueness per invite |
| PQ negotiation | Yes (hybrid) | `kem_ciphertext` appended when present |
| Protocol version string | **Gap** | Not in hash today — see §Open gaps |
| Delivery profiles | **Out of band** | Profiles verified by signature after derive; not in transcript hash |
| Rendezvous relay identity | Partial | `rendezvous_tls_spki_sha256` in signed invite only |

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

When `kem_ciphertext` present and invite supports hybrid:

```text
pq_secret = KEM_decapsulate(inviter_kem_secret, kem_ciphertext)  // joiner side
master_secret = derive_hybrid_master(
    identity_shared, ephemeral_shared, pq_secret, transcript_hash
)
```

See `hybrid_pq.py` for `derive_hybrid_master` labels.

## Derived contact state

After `master_secret`:

| Field | Derivation |
|-------|------------|
| `conversation_id` | `pairwise_{sorted_names}` lexical convention |
| `contact_id` | `SHA-256(signing_public \|\| agreement_public)` per peer |
| `transcript_hash` | stored on `Contact` |
| `ratchet` | `RatchetState.initialize(master_secret, hybrid=...)` |

## Profile handling post-pairing

Delivery profiles in `PairingRequest` / `PairingResponse` are **signed by the sender's long-term signing key** and verified with `verify_delivery_profile` before storage.

Profiles are **not** included in `transcript_hash`. Security relies on:

1. signature under known long-term key already bound in transcript; and
2. [profile-replay-policy.md](./profile-replay-policy.md) for subsequent updates.

**Open question:** should profile CBOR bytes be transcript-bound in v1.1?

## Security properties (claimed / to prove)

| Property | Status |
|----------|--------|
| MITM without breaking invite or ephemeral DH | Intended — requires review |
| Unknown key-share (different peer view) | Intended — identities in transcript |
| Replay pairing across sessions | New invite_secret per attempt |
| Downgrade PQ → classical only | **Open** — version not in transcript (P2-3) |
| Cross-protocol replay | **Open** — no domain separator on outer invite URL |

## Open gaps (tracked)

| ID | Gap | Backlog |
|----|-----|---------|
| G1 | `protocol_version` not in transcript hash | P2-4 |
| G2 | PQ downgrade if inviter strips KEM after hybrid invite | P2-3 |
| G3 | Profile bytes not in transcript | Design choice — document or fix |
| G4 | Online vs offline pairing path byte identity | Verify rendezvous path matches |
| G5 | Independent cryptographer review | P2-1 |

## Review checklist (for external auditor)

1. Confirm transcript field order matches `pairing_transcript()` in reference code.
2. Confirm HKDF labels and salt match §Master secret derivation.
3. Evaluate unknown key-share with swapped ephemeral keys.
4. Evaluate invite replay windows and `invite_secret` entropy.
5. Evaluate hybrid downgrade when `kem_ciphertext` empty on hybrid invite.
6. Confirm `conversation_id` cannot collide across distinct pairings.

## Exit criteria

- [ ] Cross-language test vector: invite + request + response → `transcript_hash` + `master_secret`
- [ ] Documented PQ downgrade policy implemented or rejected with rationale
- [ ] External review sign-off or documented findings

## References

- `packages/yakr-core/src/yakr_core/pairing.py` — `pairing_transcript`, `derive_pair_master`
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P2-2, P2-3, P2-4
