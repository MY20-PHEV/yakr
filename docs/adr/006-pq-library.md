# ADR 006: Post-Quantum Library Choice

**Status:** Accepted  
**Date:** 2026-07-07  
**Phase:** 6 — Hybrid Post-Quantum Key Agreement

## Context

Phase 6 requires ML-KEM-768 for hybrid key agreement and optional ML-DSA-65 for dual-signed invites. The reference implementation must run in CI without native OpenSSL 3.5+ PQ support and without compiling liboqs at install time.

## Decision

Use **`pqcrypto`** (v0.4.x) for ML-KEM-768 and ML-DSA-65.

- ML-KEM: `pqcrypto.kem.ml_kem_768`
- ML-DSA: `pqcrypto.sign.ml_dsa_65` (optional dual-sign on invites)

`cryptography` ML-KEM bindings are preferred long-term but require a PQ-capable backend; `liboqs-python` compiles liboqs on first import, which is too slow and fragile for CI.

## Consequences

- Wheels bundle PQClean implementations; installs are fast and deterministic.
- Public keys are 1184 bytes, ciphertexts 1088 bytes, shared secrets 32 bytes (ML-KEM-768).
- When OpenSSL/cryptography PQ support is ubiquitous, we can add a backend adapter without changing wire formats.

## Audit Status

`pqcrypto` wraps PQClean reference implementations (NIST ML-KEM / ML-DSA). This is appropriate for a reference client, not a formal security audit. Production deployments should track NIST IR and upstream PQClean advisories.
