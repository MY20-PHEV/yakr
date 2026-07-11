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

## Open review call — DH ratchet epoch rotation (F16 / R6)

**Status:** Open — seeking independent analysis  
**Backlog:** P2-1 (partial)  
**Posted:** 2026-07-11

### Summary

Yakr v1.0 uses an X25519 double ratchet (`YKDR2` wire format). Internal self-review found that in **normal bidirectional ping-pong traffic**, the **DH ratchet epoch does not rotate**: `root_key` and `dh_self_public` stay fixed while only the symmetric send/recv chains advance.

We are **not** claiming this is exploitable today. We **are** asking whether it meets the project's forward-secrecy goals and how it compares to Signal-style double-ratchet behaviour.

### Evidence

| Item | Location |
|------|----------|
| Self-review finding F16 | [docs/reviews/ratchet-self-review-2026-07-11.md](docs/reviews/ratchet-self-review-2026-07-11.md) |
| Review package R6 | [docs/security/session-ratchet-review-v1.md](docs/security/session-ratchet-review-v1.md) |
| Regression test | `packages/yakr-testkit/tests/test_ratchet_adversarial.py` → `test_bidirectional_ping_pong_uses_symmetric_chain_only` |
| Reference implementation | `packages/yakr-core/src/yakr_core/ratchet.py` — `decrypt()` sets `dh_peer_public` on first message without calling `_dh_ratchet`; DH step only runs when a **subsequent** header carries a **different** `dh_public` |
| Normative spec | [docs/spec/double-ratchet.md](docs/spec/double-ratchet.md) |

Reproduce locally:

```bash
uv run pytest packages/yakr-testkit/tests/test_ratchet_adversarial.py::test_bidirectional_ping_pong_uses_symmetric_chain_only -v
```

### Questions for reviewers

1. **Forward secrecy:** Is per-message key derivation from a fixed DH epoch (symmetric chain only) sufficient for Yakr's stated threat model, or is DH epoch rotation required?
2. **Specification gap:** Is the current `decrypt()` first-message behaviour (record peer, skip `_dh_ratchet`) intentional, an implementation bug, or a spec/impl mismatch vs [double-ratchet.md](docs/spec/double-ratchet.md)?
3. **Comparison:** How does this differ from the Signal double ratchet's receive-side DH step, and what breaks if Yakr adopted that model?
4. **Attack surface:** Can an observer or malicious relay leverage a long-lived DH epoch in ways that symmetric chain ratcheting does not mitigate?
5. **Remediation:** If change is warranted, should rotation happen on first receive, before first reply, or on another trigger? What is the minimal wire-compatible fix?

### How to respond

| Finding type | Channel |
|--------------|---------|
| **Design analysis, spec feedback, F16/R6 assessment** | Public [GitHub Discussion](https://github.com/MY20-PHEV/yakr/discussions) (preferred) or comment on a linked issue — cite `F16` / `R6` in the title |
| **Exploitable break of confidentiality or authentication** | **Private** — [GitHub Security Advisory](https://github.com/MY20-PHEV/yakr/security/advisories/new) (do not file public issues for weaponisable bugs) |

Please include:

- protocol version (`yakr-v1.0`);
- whether you recomputed [double_ratchet.json](docs/spec/test-vectors-v1/double_ratchet.json) or walked `ratchet.py`;
- impact assessment (design concern vs practical attack);
- recommended spec or implementation change, if any.

We aim to acknowledge public review responses within **14 days** and will publish a short summary of accepted findings in `docs/reviews/` (with credit if desired).

**This call does not constitute a bug bounty.** It is an invitation for cryptographic design review on an experimental protocol.


- Missing features listed as deferred in SECURITY_BACKLOG (Tor, multi-device, etc.)
- Deployment hardening of operator infrastructure (firewall, OS patching)
- Social engineering of pairing or safety-code verification

## Security documentation

| Document | Purpose |
|----------|---------|
| [SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) | P0–P3 tracked findings |
| [security/analysis-v1.md](docs/security/analysis-v1.md) | Threat model draft |
| [delivery-state-machine.md](docs/spec/delivery-state-machine.md) | Delivery semantics |
