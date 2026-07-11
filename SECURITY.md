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

## F16 / R6 — DH ratchet epoch rotation (resolved)

**Status:** **Resolved** — Option B implemented (2026-07-11)  
**Decision:** [issue #2](https://github.com/MY20-PHEV/yakr/issues/2) Option B — pairing-time DH init  
**Backlog:** P2-1 (F16 closed for pairing path)

### Summary

External review confirmed that pre-Option-B pairing sessions advanced only symmetric chains while X25519 header keys were inert. **Option B** adds `joiner_ratchet_public` / `inviter_ratchet_public` to the pairing transcript and asymmetric ratchet bootstrap at `complete_pairing`:

- Inviter defers send-side DH init until first `encrypt` (preserves joiner-first / send-before-receive).
- Joiner runs recv-side init at pairing complete.

Pairing-path traffic now rotates `root_key` and `dh_self_public` during normal bidirectional messaging. `Contact.establish` remains symmetric-chain-only (documented in [double-ratchet.md](docs/spec/double-ratchet.md)).

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
**External review:** https://github.com/MY20-PHEV/yakr/issues/2

## Open review call — DH ratchet epoch rotation (F16 / R6) — closed

<details>
<summary>Historical open review call (2026-07-11)</summary>

### Summary

Yakr v1.0 uses an X25519 double ratchet (`YKDR2` wire format). Internal self-review found that in **normal bidirectional ping-pong traffic**, the **DH ratchet does not activate**: `root_key` and `dh_self_public` stay fixed while only the pairing-derived symmetric send/recv chains advance.

External review ([issue #2](https://github.com/MY20-PHEV/yakr/issues/2)) **confirms F16** as a design issue (not a demonstrated exploit). Precise wording:

> Normal sessions advance only the pairing-derived symmetric chains. The X25519 ratchet keys exchanged in message headers do not contribute to the root key unless a peer independently changes its advertised public key.

We are **not** claiming this is exploitable today. Resolution was Option B (pairing-time DH init).

</details>

## Out of scope (for now)

- Missing features listed as deferred in SECURITY_BACKLOG (Tor, multi-device, etc.)
- Deployment hardening of operator infrastructure (firewall, OS patching)
- Social engineering of pairing or safety-code verification

## Security documentation

| Document | Purpose |
|----------|---------|
| [SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) | P0–P3 tracked findings |
| [security/analysis-v1.md](docs/security/analysis-v1.md) | Threat model draft |
| [delivery-state-machine.md](docs/spec/delivery-state-machine.md) | Delivery semantics |
