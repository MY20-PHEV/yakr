# Yakr Protocol v1.0 Interoperability

Third-party clients can verify conformance against the reference implementation using **only**:

1. [`docs/spec/yakr-protocol-v1.md`](../docs/spec/yakr-protocol-v1.md)
2. [`docs/spec/test-vectors-v1/`](../docs/spec/test-vectors-v1/)
3. This checklist

No import of `yakr_core` is required. The reference interop verifier lives at `packages/yakr-testkit/src/yakr_testkit/interop_verifier.py`.

For official **Yakr Certified** badge use (trademark, listing, review), see [CERTIFICATION.md](../CERTIFICATION.md). Self-test alone does not grant badge rights.

## Quick Start

```bash
cd yakr
uv sync --all-packages
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q
```

### Rust reference (`rust/`)

Independent Rust workspace mirroring the Python reference stack:

```bash
cd rust
cargo test
```

| Crate | Role |
|-------|------|
| `yakr-crypto` | Frozen interop vectors + AEAD/HKDF primitives |
| `yakr-core` | Double ratchet session, pairing, identity/store |
| `yakr-relay` | Mailbox relay (`yakr-relay serve`) |
| `yakr-cli` | Reference client (`yakr init/send/fetch`) |

## Conformance Checklist

### Crypto / encoding

- [x] **Hybrid KEX** — `hybrid_kex.json` master matches §3.4 derivation (`rust/yakr-crypto`)
- [x] **Mailbox tag** — `mailbox_tag.json` tag matches §3.6 (`rust/yakr-crypto`)
- [x] **Inner message** — `inner_message.json` parses as canonical sorted JSON (`rust/yakr-crypto`)

### Signed artifacts

- [x] **Invite** — CBOR decode, Ed25519 signature verifies, safety code matches (`rust/yakr-crypto`)
- [x] **Delivery profile** — CBOR decode, Ed25519 signature verifies (`rust/yakr-crypto`)

### Relay (if implementing a relay)

- [x] Rejects `mailbox_tag` ≠ 32 bytes (`rust/yakr-relay`)
- [x] Rejects `expires_at` in the past (`rust/yakr-relay`)
- [ ] Rejects ciphertext > 64 KiB
- [x] Returns 429 when per-tag blob cap exceeded (`rust/yakr-relay`)
- [x] Does not decrypt ciphertext (`rust/yakr-relay`)

### Client (minimal)

- [x] Pairwise master derivation (classical or hybrid) matches vectors (`rust/yakr-core`)
- [x] Encrypt/decrypt round-trip for inner message format (`rust/yakr-crypto`, `rust/yakr-core`)
- [x] Fetch uses epoch lookback (current + N prior epochs) (`rust/yakr-core`, `rust/yakr-cli`)

## Independent Verifier API

```python
from yakr_testkit.interop_verifier import (
    verify_all_vectors,
    verify_delivery_profile_vector,
    verify_hybrid_kex_vector,
    verify_inner_message_vector,
    verify_invite_vector,
    verify_mailbox_tag_vector,
)

verify_all_vectors("docs/spec/test-vectors-v1")
```

## Reporting Issues

Interop failures should include:

- Vector file name and field
- Your implementation language and crypto libraries
- Expected vs actual hex (first 16 bytes sufficient for secrets)

## Version Freeze

`yakr-v1.0` vectors are frozen. New vectors require `test-vectors-v2/` and a protocol revision.
