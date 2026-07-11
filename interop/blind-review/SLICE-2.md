# Blind Review — Slice 2 (Negative Vectors)

**Prerequisite:** [SLICE-1](./SLICE-1.md) complete (or parallel if you already understand pairing/ratchet).

## Goal

For each vector in `docs/spec/test-vectors-v1/negative/*.json`, your implementation must:

1. **Reject** the input (`must_reject: true`)
2. Return or record the **`normative_error_code`** from [negative-vector-outcomes-v1.md](../../docs/spec/negative-vector-outcomes-v1.md)
3. Ensure **`persistent_state_must_change: false`** — ratchet/pairing durable state unchanged by the rejecting call
4. Treat **`retryable: false`** — same bytes must not succeed on retry

`error_contains` is **reference-hint only**; do not match Python exception substrings.

## Vector files

| File | Operations |
|------|------------|
| `negative/pairing.json` | `pairing_validate` |
| `negative/cbor.json` | `pairing_request_decode`, `pairing_response_decode` |
| `negative/invite.json` | `invite_verify` |
| `negative/outer_blob.json` | `outer_blob_decode` |
| `negative/ratchet.json` | `ratchet_decrypt*` (uses `double_ratchet.json` bootstrap) |

## Tasks

1. Implement rejection handlers for each `operation` type.
2. Map failures to `normative_error_code` (stable string, not localized text).
3. For ratchet vectors: snapshot chain state immediately before the rejecting decrypt; confirm identity after rejection.
4. Produce a report table:

```text
| vector name | normative_error_code | state unchanged | pass |
|-------------|----------------------|-----------------|------|
| pairing-classical-unexpected-kem | YAKR_E_PAIRING_UNEXPECTED_KEM | yes | PASS |
...
```

## Optional cross-check

After your harness passes, you may compare against the steward reference verifier:

```bash
uv run python -c "
from yakr_testkit.interop_verifier import verify_all_negative_vectors
verify_all_negative_vectors('docs/spec/test-vectors-v1')
"
```

This step is **optional** and **not** part of the blind slice; use only to confirm your codes align.

## Success

All 16 vectors pass with correct codes and no state advance on rejection.

## Feedback

Complete [FEEDBACK-TEMPLATE.md](./FEEDBACK-TEMPLATE.md) — especially “spec gaps” and “error code clarity”.
