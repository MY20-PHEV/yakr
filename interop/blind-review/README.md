# Yakr Blind Implementation Review — Package

**Status:** Open (post–Phase 11, P11-4)  
**Purpose:** Validate that `yakr-v1.0` is implementable from **normative specifications and frozen vectors alone**, without reading the Python or Rust reference code.

## Who this is for

- Independent cryptographers and protocol engineers
- Implementers evaluating Yakr before committing to a client or library
- Reviewers answering: *“Could I build a conforming slice without peeking at the reference?”*

## Rules of engagement

1. **Do not read** `packages/yakr-core/`, `packages/yakr-cli/`, `rust/`, or `apps/` while working a slice.
2. **Do not run** `interop_verifier.py` until your own harness is written (Slice 2 may compare outcomes).
3. **You may use** any crypto library; document choices in feedback.
4. **You may read** only files listed in [MANIFEST.md](./MANIFEST.md).
5. Report confusion, missing fields, and ambiguous normative text in [FEEDBACK-TEMPLATE.md](./FEEDBACK-TEMPLATE.md).

## Suggested order

| Slice | Goal | Time box (guide) |
|-------|------|------------------|
| [SLICE-1](./SLICE-1.md) | Positive vectors: hybrid KEX, pairing transcript, double ratchet bootstrap | 1–3 days |
| [SLICE-2](./SLICE-2.md) | Negative vectors: normative error codes + no state advance | 1–2 days |

## Deliverables

For each slice, submit (GitHub issue, discussion, or email to steward):

- Language and crypto libraries used
- Pass/fail per vector name
- For failures: expected vs actual (hex prefix sufficient for secrets)
- For Slice 2: table of `normative_error_code` your implementation returns
- Completed feedback template (confusion log)

## Bundle

To produce a tarball containing only allowed files:

```bash
./scripts/create_blind_review_bundle.sh
```

Output: `dist/yakr-blind-review-v1.tar.gz` (spec + vectors + this directory).

## Success criteria (project)

Phase 11 claims third-party readiness. This package succeeds when:

- At least one external reviewer completes Slice 1 without reference code
- Slice 2 error codes match [negative-vector-outcomes-v1.md](../../docs/spec/negative-vector-outcomes-v1.md)
- Feedback yields zero **blocking** spec ambiguities, or those ambiguities land in `errata-v1.md`

## References (allowed)

See [MANIFEST.md](./MANIFEST.md). Normative entry point: [yakr-protocol-v1.md](../../docs/spec/yakr-protocol-v1.md).
