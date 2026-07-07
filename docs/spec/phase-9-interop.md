# Phase 9 — Public Protocol and Interop

**Protocol:** `yakr-v1.0`  
**Status:** Implemented

## Goal

Freeze Yakr as an implementable open standard with independent client interop and relay abuse conformance.

## Deliverables

| Artifact | Path |
|----------|------|
| Normative spec | `docs/spec/yakr-protocol-v1.md` |
| Test vectors | `docs/spec/test-vectors-v1/` |
| Security analysis | `docs/security/analysis-v1.md` |
| Interop guide | `interop/README.md` |
| Independent verifier | `packages/yakr-testkit/src/yakr_testkit/interop_verifier.py` |

## Exit Criteria

- [x] Second client (interop verifier) passes suite using only public spec + vectors
- [x] Security analysis reviewed against stated threat model
- [x] Versioning and extension rules documented in `yakr-protocol-v1.md` §2
- [x] Relay passes abuse-limit conformance tests (`test_phase9_relay_abuse.py`)

## Demo

```bash
uv sync --all-packages
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q
```

## Test Vectors

| File | Checks |
|------|--------|
| `hybrid_kex.json` | ML-KEM hybrid master derivation |
| `invite.json` | CBOR invite + Ed25519 + safety code |
| `delivery_profile.json` | Signed delivery profile |
| `mailbox_tag.json` | HMAC mailbox tag |
| `inner_message.json` | Canonical inner JSON |

## Relay Abuse Limits

Reference `BlobStore` enforces:

- `mailbox_tag` = 32 bytes
- `expires_at` > now (ms)
- `ciphertext` ≤ 64 KiB
- ≤ 256 blobs per tag (429 when exceeded; tests use cap of 3)
