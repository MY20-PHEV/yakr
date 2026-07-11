# Security Policy

**Project maturity:** Experimental — not production-audited. See [README.md](README.md) and [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md).

## Supported versions

| Protocol / branch | Security fixes |
|-------------------|----------------|
| `yakr-v1.0` draft on `main` | Best effort while experimental |
| Older reference snapshots | Not supported |

There is **no** production security commitment. Do not deploy Yakr for high-risk communications without independent review.

## Reporting a vulnerability

**Please do not open public GitHub issues for exploitable security bugs.**

1. Open a **private** report via [GitHub Security Advisories](https://github.com/MY20-PHEV/yakr/security/advisories/new) for this repository, **or**
2. Email the repository owner (see GitHub profile contact) with subject `Yakr security`.

Include:

- affected component (client, relay, spec, crypto);
- protocol version (`yakr-v1.0`, etc.);
- steps to reproduce;
- impact assessment;
- proof-of-concept if available.

We aim to acknowledge reports within **7 days**. Coordinated disclosure is preferred; we will agree on a timeline before any public write-up.

## Cryptographic and protocol findings

For design-level issues (pairing transcript, ratchet, relay authorization, TLS pin lifecycle):

- Reference [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) and [docs/reviews/](docs/reviews/).
- Normative behaviour is defined in [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md) and extension specs.
- **Pairing transcript review:** [docs/spec/pairing-transcript-v1.md](docs/spec/pairing-transcript-v1.md)
- **Session / double-ratchet review package:** [docs/security/session-ratchet-review-v1.md](docs/security/session-ratchet-review-v1.md) (test vectors in `docs/spec/test-vectors-v1/`)

External reviews are welcome; see saved critiques in `docs/reviews/`.

## F16 / R6 — DH ratchet epoch rotation (closed)

**Status:** **Closed** (pairing path resolved, 2026-07-11)  
**Decision:** [issue #2](https://github.com/MY20-PHEV/yakr/issues/2) — Option B (pairing-time DH init)  
**Discussion:** [#1](https://github.com/MY20-PHEV/yakr/discussions/1) (closed)

### What was fixed

External review confirmed that pre-Option-B **pairing** sessions advanced only symmetric chains while X25519 header keys were inert. **Option B** adds `joiner_ratchet_public` / `inviter_ratchet_public` to the pairing transcript and asymmetric ratchet bootstrap:

- Inviter defers send-side DH init until first `encrypt` (preserves joiner-first / send-before-receive).
- Joiner runs recv-side init at pairing complete.

Pairing-path traffic now rotates `root_key` and `dh_self_public` during normal bidirectional messaging.

### What was not in scope for #2

`Contact.establish()` remains **symmetric-chain-only** — a non-normative compatibility path for tests and manual bootstrap, not transcript-bound production pairing. It is documented, not hidden. Universal “Double Ratchet” branding for all v1.0 session creation awaits either migrating `establish` to the same model or deprecating it ([double-ratchet.md](docs/spec/double-ratchet.md), backlog P2-8).

### Evidence

| Item | Location |
|------|----------|
| External review | [docs/reviews/external-ratchet-review-f16-issue-2-2026-07-11.md](docs/reviews/external-ratchet-review-f16-issue-2-2026-07-11.md) |
| Pairing transcript spec | [docs/spec/pairing-transcript-v1.md](docs/spec/pairing-transcript-v1.md) |
| Double ratchet spec | [docs/spec/double-ratchet.md](docs/spec/double-ratchet.md) |
| Regression tests | `test_pairing_path_rotates_dh_epoch`, `test_contact_establish_ping_pong_does_not_rotate_dh_epoch` in `test_ratchet_adversarial.py` |
| Reference implementation | `packages/yakr-core/src/yakr_core/ratchet.py` — `_pairing_send_init`, `_pairing_recv_init`, `pending_pairing_dh_ratchet_peer` |

```bash
uv run pytest packages/yakr-testkit/tests/test_ratchet_adversarial.py::test_pairing_path_rotates_dh_epoch -v
```

**Discussion thread:** https://github.com/MY20-PHEV/yakr/discussions/1  
**External review:** https://github.com/MY20-PHEV/yakr/issues/2 (closed)

## Out of scope (for now)

- Missing features listed as deferred in SECURITY_BACKLOG (Tor, multi-device, etc.)
- Deployment hardening of operator infrastructure (firewall, OS patching)
- Social engineering of pairing or safety-code verification

## Security documentation

| Document | Purpose |
|----------|---------|
| [SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) | P0–P3 tracked findings |
| [security/analysis-v1.md](docs/security/analysis-v1.md) | Threat model draft |
| [delivery-state-machine.md](docs/spec/delivery-state-machine.md) | Delivery semantics (normative) |
| [errata-v1.md](docs/spec/errata-v1.md) | v1.0 errata register |
