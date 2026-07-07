# Phase 6 — Hybrid Post-Quantum Key Agreement

**Protocol:** `yakr-v0.6`  
**Status:** Implemented

## Goal

Add ML-KEM-768 hybrid key agreement for harvest-now-decrypt-later resistance while preserving classical-only fallback.

## Hybrid Invite

```bash
yakr invite create --hybrid --port 8090
```

Hybrid invites (`yakr-v0.6`) include:

- `hybrid_pq` capability flag
- Inviter ML-KEM-768 public key
- Optional ML-DSA-65 dual signature alongside Ed25519

## KEX Combiner

```text
x_secret  = X25519(identity) || X25519(ephemeral)
pq_secret = ML-KEM-768 encaps/decaps
master    = HKDF-SHA256(x_secret || pq_secret, salt=transcript, info="yakr/v0.6/hybrid-master")
```

## PQ Rekey Policy

Sessions require rekey after 7 days or 10,000 messages (`RekeyRequiredError` on send).

## Library

See [ADR 006](../adr/006-pq-library.md) — `pqcrypto` for ML-KEM-768 and ML-DSA-65.

## Exit Criteria

- [x] Hybrid-capable clients establish session with PQ component
- [x] Classical-only peer negotiates fallback when `hybrid_pq` absent
- [x] Test vectors pass in CI across core + testkit verifier
- [x] ADR documents PQ library choice and audit status
