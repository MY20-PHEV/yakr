# Blind Review — Allowed Files

Reviewers may read **only** these paths (plus their own implementation code). Anything else is out of scope for the blind review.

## Normative specifications

| Path | Why |
|------|-----|
| [docs/spec/yakr-protocol-v1.md](../../docs/spec/yakr-protocol-v1.md) | Core wire protocol |
| [docs/spec/pairing-transcript-v1.md](../../docs/spec/pairing-transcript-v1.md) | Pairing transcript (Option B) |
| [docs/spec/double-ratchet.md](../../docs/spec/double-ratchet.md) | Ratchet bootstrap and message format |
| [docs/spec/negative-vector-outcomes-v1.md](../../docs/spec/negative-vector-outcomes-v1.md) | Normative rejection codes (Slice 2) |
| [docs/spec/errata-v1.md](../../docs/spec/errata-v1.md) | Clarifications and deferrals |

## Frozen vectors

| Path | Why |
|------|-----|
| [docs/spec/test-vectors-v1/hybrid_kex.json](../../docs/spec/test-vectors-v1/hybrid_kex.json) | Slice 1 |
| [docs/spec/test-vectors-v1/pairing_transcript.json](../../docs/spec/test-vectors-v1/pairing_transcript.json) | Slice 1 |
| [docs/spec/test-vectors-v1/double_ratchet.json](../../docs/spec/test-vectors-v1/double_ratchet.json) | Slice 1 |
| [docs/spec/test-vectors-v1/negative/](../../docs/spec/test-vectors-v1/negative/) | Slice 2 (all `*.json`) |

## Review instructions

| Path | Why |
|------|-----|
| [interop/blind-review/README.md](./README.md) | This package |
| [interop/blind-review/SLICE-1.md](./SLICE-1.md) | Slice 1 tasks |
| [interop/blind-review/SLICE-2.md](./SLICE-2.md) | Slice 2 tasks |
| [interop/blind-review/FEEDBACK-TEMPLATE.md](./FEEDBACK-TEMPLATE.md) | Report template |

## Explicitly forbidden during blind work

- `packages/yakr-core/`, `packages/yakr-cli/`, `packages/yakr-relay/`
- `packages/yakr-testkit/src/yakr_testkit/interop_verifier.py` (until comparing after Slice 2)
- `rust/` entire workspace
- `apps/`
- Git history blame on reference implementation files

## Optional (non-normative context)

These are **not required** for conformance but may help motivation:

- [whitepaper.md](../../whitepaper.md)
- [docs/reviews/phase-11-independent-critique-2026-07-11.md](../../docs/reviews/phase-11-independent-critique-2026-07-11.md)

Do not treat whitepaper prose as overriding normative spec.
