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
