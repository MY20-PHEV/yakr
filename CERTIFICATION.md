# Yakr Protocol Certification Program

**Status:** Draft (program not yet accepting applications)  
**Protocol baseline:** `yakr-v1.0`  
**Companion:** [interop/README.md](interop/README.md) · [NOTICE.md](NOTICE.md)

**Yakr Protocol** is an **open messaging protocol** (public name; short form **Yakr** in wire tags and packages). The reference Python implementation demonstrates correctness; **production messengers and relay operators are expected to be independent products**. Certification is how implementers show conformance and how users find compatible software — without a central Yakr messaging platform.

Formal badge name: **Yakr Protocol Certified** (short: **Yakr Certified**).

### Project maturity (all categories)

| Dimension | Status |
|-----------|--------|
| Reference implementation | Broad phase coverage |
| Protocol stability | Draft (`yakr-v1.0` interop baseline) |
| Security maturity | **Experimental** — composition not externally audited |
| Production recommendation | **No** |

See [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md). Certification attests to **wire compatibility**, not production security.

---

## What certification means

A **Yakr Certified** product has passed the published conformance tests for its category (client and/or relay). Certification attests to **wire-format and behavioral compatibility** with `yakr-v1.0`, not to operational security, legal safety, or fitness for a particular threat model.

| Certified means | Certified does **not** mean |
|-----------------|----------------------------|
| Passes interop vectors and category test suite | Audited for nation-state adversaries |
| Implements pairing-gated relay rules per spec | Approved for whistleblowers without ops discipline |
| Uses outbound poll receive path on constrained mobile (if claiming mobile client) | Run by the Yakr project |
| Relay abuse limits match reference (if relay) | Immune to metadata timing on relays |

Use honest public wording: **“Yakr v1.0 Compatible”** or **“Yakr Certified — Client v1.0”** — not “military grade” or “untraceable.”

---

## Killer feature (what certified products must preserve)

Yakr’s distinguishing property:

> **Your relay network is your pairing graph.** Messages are end-to-end encrypted and delivered through **store-and-forward mailboxes operated only by people you have pairwise paired with** — not a global relay pool, not a single platform operator, and not wire-level P2P pretending phones are inbound-reachable on cellular. Peers learn relay URLs and TLS pins from **signed delivery profiles** in the trust graph (including transitive pins for paired operators you have not met directly).

Certified clients and relays MUST NOT weaken this model (e.g. open anonymous relay directories, public global mailboxes, or mandatory central accounts).

---

## Certification categories

### Yakr Certified — Client v1.0

For messenger apps, CLI tools, or libraries that act as a Yakr **user endpoint**.

**Required:**

- Pairwise pairing and master secret derivation per `docs/spec/yakr-protocol-v1.md`
- E2E encrypt/decrypt of inner messages; delivery profile verify
- **Relay authorization:** advertise only relays permitted by `docs/spec/relay-authorization.md`
- **Receive path:** outbound poll to paired/profile/presence-resolved relays (ADR 008); no dependence on inbound phone listener for correctness
- **Send path:** store opaque blobs on recipient mailboxes via paired relays; ordered failover encouraged
- Pass all applicable items in [interop/README.md](interop/README.md) and `docs/spec/test-vectors-v1/`
- Pass client interop pytest subset (published when program opens)

**Optional extensions** (separate badge lines when available):

- Hybrid post-quantum pairing (`yakr-v0.6+`)
- Minimal presence (`yakr-v1.1/presence`)
- Pairing-anchored TLS (`docs/spec/tls-endpoints.md`)
- Optional platform wake (`yakr-v1.2/wake`, ADR 011) — poll remains required; silent push as fetch hint only

### Yakr Certified — Relay v1.0

For mailbox / rendezvous servers implementing `yakr-relay` semantics.

**Required:**

- HTTPS with operator-controlled certificates (pins in client profiles, not public CA trust for Yakr auth)
- `/v1/blobs` store/fetch, expiry enforcement, opaque ciphertext only
- Abuse limits per protocol §4.5 and reference relay (`test_phase9_relay_abuse.py`)
- `/v1/pair*` if advertising rendezvous (see `docs/spec/relay-rendezvous.md`)
- No decryption of message plaintext; minimal logging policy per `docs/REFERENCE_DESIGN.md`

---

## Self-test vs official certification

Anyone may run conformance tests **without** a badge:

```bash
uv sync --all-packages
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q
```

```python
from yakr_testkit.interop_verifier import verify_all_vectors
verify_all_vectors("docs/spec/test-vectors-v1")
```

**Official certification** (when the program is open) adds:

1. Submitted build + test report (or hosted test session)
2. Review of relay-authorization and mobile receive-path claims
3. Permission to use **Yakr Certified** name and badge artwork
4. Listing in the public implementers directory (URL TBD)

Self-test success does not grant trademark use.

---

## Badge and trademark

The **Yakr Protocol** name and **Yakr Protocol Certified** badge are controlled by the project steward — see [NOTICE.md](NOTICE.md) for UK search summary, independence disclaimers, and trademark status.

**Allowed without certification:**

- “Implements Yakr protocol v1.0” (factual)
- Link to this repo and the normative spec

**Requires certification agreement:**

- “Yakr Certified” / certified badge artwork
- Implying endorsement by the steward beyond compatibility

Forks and independent implementations are welcome; they must not use the certified badge without passing review.

---

## Fees (draft)

Fees fund conformance review and steward costs (CI, spec maintenance, security mailbox) — **not** access to the protocol.

| Tier | Audience | Draft fee model |
|------|----------|-----------------|
| **Open source / nonprofit** | OSS clients, research | Free listing after self-test + lightweight review |
| **Commercial client** | App stores, enterprise messengers | One-time certification + annual renewal |
| **Commercial relay** | Hosted relay operators | One-time certification + annual renewal |
| **Re-certification** | Major version bump | Delta review fee |

Exact pricing will be published before applications open. The spec and test vectors remain **free and public** regardless.

---

## Application process (when open)

1. **Register interest** — issue or email on the public tracker (TBD)
2. **Self-test** — submit pytest + `verify_all_vectors` output
3. **Category checklist** — client and/or relay form
4. **Review** — steward or delegated reviewer; may request fixes or spec errata
5. **Grant** — certificate ID, badge assets, directory listing
6. **Renewal** — annual re-run of vectors; revoke on fraud or spec violation

Target review time (goal): 4–8 weeks for first commercial application.

---

## Revocation

Certification may be revoked if:

- Product fails renewal tests against current vectors
- Misuse of badge or false compatibility claims
- Deliberate bypass of pairing-gated relay rules while claiming certification
- Spec-breaking behavior without disclosure

Revoked products must remove badge use within 30 days.

---

## Steward role

The steward maintains:

- Normative spec and errata
- Frozen `test-vectors-v1/` and interop verifier
- Certification criteria and badge guidelines
- Security contact for the **reference** implementation

The steward does **not** operate a global message service, run public relays for end users, or mandate a single commercial messenger.

---

## For implementers building a business

Certification is **compatibility**, not your moat. Messengers, managed relays, support, and UX are yours to monetize. The badge helps users and orgs find software that interoperates on the same pairing-gated social relay model.

See also: [whitepaper.md](whitepaper.md) §2.1 (target users), [docs/security/analysis-v1.md](docs/security/analysis-v1.md).

---

## References

- [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md)
- [interop/README.md](interop/README.md)
- [docs/spec/relay-authorization.md](docs/spec/relay-authorization.md)
- [docs/adr/008-nat-reachability-and-mobile-delivery.md](docs/adr/008-nat-reachability-and-mobile-delivery.md)
