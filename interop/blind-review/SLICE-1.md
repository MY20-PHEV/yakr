# Blind Review — Slice 1 (Positive Vectors)

**Prerequisite:** Read [MANIFEST.md](./MANIFEST.md). Do not open reference implementation source.

## Goal

Implement verifiers for three frozen vector files using only normative spec text:

1. `hybrid_kex.json`
2. `pairing_transcript.json` (classical **and** hybrid entries)
3. `double_ratchet.json` (bootstrap + at least one encrypt/decrypt round-trip per vector)

## Tasks

### 1. Hybrid KEX (`hybrid_kex.json`)

- Derive `master_secret` per `yakr-protocol-v1.md` §3.4 and `pairing-transcript-v1.md` hybrid path.
- Compare output to `master_secret_hex` in each vector.
- Document which ML-KEM-768 API you used.

### 2. Pairing transcript (`pairing_transcript.json`)

- Reconstruct `pairing_transcript_hash` from vector fields.
- Derive `master_secret` (classical and hybrid vectors).
- Compare to `master_secret_hex`.

### 3. Double ratchet (`double_ratchet.json`)

- From `master_secret_hex`, derive root and send/recv chain keys per `double-ratchet.md`.
- Verify first-message encrypt/decrypt matches `ciphertext_hex` / `plaintext_hex` where provided.
- Confirm header layout (`YKDR2` magic, DH public, counters).

## Output format

```text
SLICE-1 REPORT
language: <e.g. Go 1.22>
crypto: <e.g. circl, liboqs, etc.>

hybrid_kex.json:
  - <vector name>: PASS|FAIL (<note>)

pairing_transcript.json:
  - classical-pairing-v1: PASS|FAIL
  - hybrid-pairing-v1: PASS|FAIL

double_ratchet.json:
  - <vector name>: PASS|FAIL
```

## Common pitfalls (intentional checks)

- Hybrid vs classical domain separation (`yakr/v0.6/hybrid-master` vs pair-master info)
- Transcript field order and included ratchet public keys (Option B)
- HKDF info strings for double-ratchet chains (`yakr/v1.0/double-ratchet-*`)
- Endianness of ratchet counters in header (`>II`)

## When stuck

Log the spec section, vector field name, and your interpretation in [FEEDBACK-TEMPLATE.md](./FEEDBACK-TEMPLATE.md). Do not look at reference code; ask via GitHub issue if needed.

## Next

[SLICE-2](./SLICE-2.md) — negative vectors and normative error codes.
