# External Protocol Review — GitHub Follow-Up (10 July 2026)

**Status:** Reference (not normative)  
**Source:** Independent review of the live repository ([MY20-PHEV/yakr](https://github.com/MY20-PHEV/yakr)) after P0 hardening and publication  
**Audience:** Project maintainers; informs P0–P3 backlog prioritisation  
**Predecessor:** [external-critique-2026-07-10.md](./external-critique-2026-07-10.md)  
**Follow-up:** [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md), [ADR 012](../adr/012-relay-capability-tokens.md), [relay-capability-v1.md](../spec/relay-capability-v1.md)

---

Ellis, the live repository is a substantial step forward from the version I first reviewed.

You have not merely edited the prose. You have taken the critique and turned the highest-risk points into specifications, code changes, tests, and tracked security work. That is exactly the right response.

**My view now:** Yakr has moved from "ambitious protocol prototype" toward "serious experimental protocol implementation."

It is still correctly labelled as experimental and not production-ready, but the project is beginning to have the shape that outside implementers and security reviewers could engage with meaningfully.

---

## What has improved most

### The project identity is now very clear

The README opens with the right distinguishing idea:

> Your relay network is your pairing graph.

It immediately explains that mailboxes belong to people in the trust graph rather than one central provider or an anonymous public relay pool. It also makes outbound polling on constrained mobile devices part of the fundamental model rather than pretending phones are always reachable.

That is much clearer than the earlier emphasis on rotating multi-hop routes.

The current presentation now says, in effect:

**Core Yakr:**

- E2E encryption
- socially scoped mailboxes
- offline store-and-forward
- replaceable relay infrastructure

**Optional privacy layers:**

- two-hop routing
- padding
- delays
- decoy fetches

I think that hierarchy is right.

### The security backlog has become genuinely useful

This is no longer a generic TODO list. It now records:

- protocol maturity;
- security maturity;
- audit status;
- production recommendation;
- individual security findings;
- implementation status;
- explicit feature deferrals.

More importantly, several P0 findings are now actually implemented:

- atomic send persistence;
- atomic receive persistence;
- fetch serialization;
- stale-receipt handling;
- delivery-profile rollback protection.

The decision not to begin Tor, radio transports, multi-device sync, or additional deployment work until more protocol-hardening is complete is good discipline.

### The atomic persistence work is a major improvement

The recent implementation does the important thing I was worried about:

```text
ratchet advancement
+ contact state
+ outbound ciphertext
+ pending delivery record
= one SQLite transaction
```

The implementation stores the already-created outer ciphertext with the pending message, allowing retries without ratcheting and encrypting again.

That is a particularly important correction.

Previously, retry behaviour risked becoming:

```text
send fails
  → encrypt again
  → new ratchet step
  → new ciphertext
  → old message state becomes complicated
```

Now the model is:

```text
encrypt once
  → atomically persist ratchet state and ciphertext
  → retry the same opaque blob
```

That is much easier to reason about and far less dangerous.

The added rollback and key-reuse tests are valuable too, although you correctly still describe process-level kill -9 crash testing as unfinished rather than claiming complete crash assurance.

### The receipt handling is much more precise

The new rule for unknown or stale receipts is correct:

```text
Receipt does not match pending msg_id:
    do not delete anything

But successful decryption consumed a receive sequence:
    still persist receive ratchet state
```

That distinction is subtle and important.

Ignoring the entire receipt—including ratchet advancement—could desynchronise the session. Applying it loosely could clear an unrelated pending message. The implementation now separates those concerns.

The same reasoning has been applied to rejected profile updates: a rollback must not replace the profile, but the valid encrypted message still consumed a sequence and therefore receive state must advance.

That is the sort of edge-case thinking messaging protocols need.

### Profile rollback protection is a good addition

The new rules are sensible:

| Condition | Action |
|-----------|--------|
| `incoming.version > stored` | accept |
| same version + identical bytes | accept as idempotent replay |
| same version + different content | reject conflict |
| `incoming.version < stored` | reject rollback |

This protects against replaying an older legitimately signed profile to restore obsolete relay URLs or TLS pins.

One future refinement may be needed when profile state becomes more complex: a single integer version assumes one authoritative linear update stream. That is perfectly suitable for your v1 single-device identity model. It would become harder under multi-device publishing, but you have wisely deferred multi-device sync.

### The independent Rust work is becoming meaningful

The Rust side is no longer merely a vector parser.

Recent commits describe:

- crypto primitives;
- invite verification;
- delivery-profile verification;
- ratchet and pairing;
- persistent core state;
- relay implementation;
- CLI send/fetch behaviour;
- full Rust workspace tests in CI.

The CI now tests both the Python packages and the complete Rust workspace.

That significantly improves confidence in the protocol description because two languages force implicit assumptions into the open.

I would still avoid calling the Rust implementation "independent security validation." It is an **independent implementation and interoperability check**, which is already valuable. Security independence requires separate authorship and review methodology, not merely a different language.

---

## One important issue in the proposed capability design

The relay-capability proposal is pointed in the right direction, but the **current verification model has an authorisation gap**.

The capability contains:

- `capability_id`
- relay identity
- permissions
- expiry
- `auth_public`
- signature

…and the relay verifies that `auth_public` signed the capability.

**The problem:** a self-signed public key proves internal consistency, but not authorisation.

An attacker can generate:

- attacker private key
- attacker public key
- arbitrary `capability_id`
- `permission = post`
- future expiry
- valid signature

…and satisfy all five currently listed verification rules.

The relay still needs a trusted reason to accept that particular capability.

Your ADR apparently considers maintaining an allow-list, but the normative capability specification currently does not make that trust anchor explicit. The verification rules only require signature validity.

**I would change the design so one of these is mandatory.**

### Option A: relay-issued bearer capability

During operator pairing, the relay creates a random capability:

```text
capability_id = random 256 bits
capability_secret = random 256 bits
```

The relay stores a hash or verifier.

Requests prove possession using a MAC:

```text
MAC(
    capability_secret,
    method || path || body_hash || timestamp || nonce
)
```

**Advantages:** simple; genuinely authorised by the relay; no user identity exposed; easy expiry and revocation; no self-signature ambiguity.

### Option B: relay-signed capability

The relay signs:

- `capability_id`
- permissions
- expiry
- client auth public key

The client then signs individual requests using the associated private key.

The relay verifies:

1. the capability was issued by the relay;
2. the request was signed by the capability holder.

This gives stronger proof-of-possession and avoids bearer-token theft being sufficient.

### Option C: registered derived public key

Your deterministic per-relay key derivation can still work, but the relay must first **register** the resulting `auth_public` through an already authenticated operator-pairing exchange.

Then the relay verification rule becomes:

```text
auth_public MUST be registered and active for this relay capability
```

—not merely:

```text
signature verifies under the included auth_public
```

This is probably closest to your current design.

**I would make this a P1 blocker before implementing the capability layer.** The overall direction is sound; the missing part is the trust anchor.

---

## A second issue: deterministic capability IDs may affect rotation

The proposed derivation appears to use:

```text
master_secret + relay name + TLS pin
```

to derive the capability seed.

Unless an epoch, generation counter, or random issuance salt is included, the same pairing and relay descriptor will regenerate the same:

- `capability_id`
- auth keypair

…indefinitely.

That weakens the stated rotation property.

Expiry rotates the signed object, but the relay-visible pseudonym remains stable.

You likely want:

```text
capability_seed = HKDF(
    master_secret,
    relay_identity || capability_generation || random_issuance_salt
)
```

Then a new capability actually produces:

- new `capability_id`
- new auth keypair

The generation/salt can be carried inside the encrypted profile update.

There is a trade-off:

- deterministic recovery is convenient;
- actual unlinkable rotation requires changing input.

I would state that decision explicitly.

---

## The current major risks are now concentrated

Earlier there were concerns spread everywhere. Now the remaining high-value work is much more focused.

### 1. Pairing and transcript security

The backlog still correctly leaves these open:

- complete transcript construction;
- PQ downgrade prevention;
- protocol-version downgrade prevention;
- independent ratchet review.

This is probably now the **most important security work**.

The questions are:

- What exact bytes are authenticated?
- Are identities bound to ephemeral keys?
- Are negotiated capabilities included?
- Are protocol versions included?
- Are relay/profile exchanges bound to the pairing?
- Can messages be replayed between sessions?
- Can two parties derive the same secret while disagreeing about who the peer is?

These deserve one precise normative transcript document.

### 2. Ratchet correctness beyond persistence

Atomic storage fixes one major implementation hazard, but the ratchet itself still needs scrutiny around:

- out-of-order delivery;
- skipped-key limits;
- maliciously huge sequence gaps;
- DH-ratchet transitions;
- duplicate DH public keys;
- malformed public keys;
- concurrent sends;
- key deletion;
- post-compromise recovery claims.

Your backlog correctly does not treat atomic persistence as equivalent to cryptographic validation.

### 3. TLS pin recovery

TLS pinning gives Yakr strong pairing-anchored endpoint authentication, but operational recovery is hard.

You still need answers for:

| Scenario | Question |
|----------|----------|
| Relay certificate changed normally | How is the new pin authenticated? |
| Relay host is compromised | How is it revoked? |
| Operator loses relay key | Can contacts recover without re-pairing? |
| Old signed profiles are replayed | Can they restore a compromised pin? |
| Two relay keys overlap during rotation | How long? |

The backlog correctly leaves this open.

This is not a small operational detail. Pin lifecycle becomes part of the protocol's trust model.

### 4. Real mobile behaviour

The repository has a mobile package and Android shell, but the project correctly still marks physical-device evidence as open:

- Doze;
- killed process;
- reboot;
- battery use;
- wake reliability;
- duplicate behaviour under poor networking.

That is honest.

The mobile implementation is currently evidence that Yakr can be packaged for mobile—not yet evidence that it behaves like a reliable everyday messenger.

---

## A few repository-level observations

### Add a licence soon

The README currently ends with:

```markdown
## License

TBD
```

For an open protocol seeking third-party implementations, this is becoming important.

You probably need to choose separately:

| Asset | Suggested licence |
|-------|-------------------|
| Specification/documentation | CC BY 4.0 or similar |
| Reference implementation | Apache-2.0 or MIT + Apache-2.0 dual licence |

Apache-2.0 is attractive for the code because it contains an explicit patent grant.

This deserves legal thought, but leaving it TBD may discourage early contributors or independent implementers.

### Add document precedence

The README provides a good document index but still does not visibly explain what wins when documents disagree.

Suggested **normative precedence:**

1. `yakr-protocol-v1.md`
2. Normative extension specifications
3. Published errata
4. Frozen test vectors
5. Reference design
6. Whitepaper and implementation history

The whitepaper should explain intent; the normative spec must determine interoperability.

### Consider a security-policy file

For a security protocol repository, add `SECURITY.md` covering:

- private vulnerability reporting;
- supported protocol versions;
- disclosure expectations;
- no production-security claim;
- how cryptographic findings should be reported.

GitHub can surface this automatically to researchers.

### Add code-quality checks gradually

Current CI runs Python tests and Rust tests, which is a good baseline.

The next useful additions would be:

- `ruff check`
- `ruff format --check`
- `mypy` or `pyright` on core modules
- `cargo fmt --check`
- `cargo clippy -- -D warnings`

For the protocol parsers later:

- property tests
- fuzzing
- malformed vectors
- cross-language differential tests

I would not let linting distract from protocol work, though.

---

## My updated verdict

| Area | Current assessment |
|------|-------------------|
| Core idea | Excellent |
| Positioning | Clear and distinctive |
| Documentation honesty | Excellent |
| Delivery semantics | Strong draft |
| Crash-safe persistence | Substantially improved |
| Replay/receipt handling | Good direction |
| Cross-language interop | Meaningful |
| Security engineering process | Very encouraging |
| Relay capability redesign | Good goal; authorisation trust anchor needs correction |
| Pairing/transcript assurance | Major remaining priority |
| Ratchet assurance | Major remaining priority |
| Mobile evidence | Still open |
| Production readiness | Correctly: no |

The most impressive part is the feedback loop:

```text
external concern
  → documented finding
  → priority assigned
  → normative behaviour defined
  → implementation changed
  → test added
  → remaining limitation still recorded
```

That is exactly how a serious protocol project should evolve.

You have done an extraordinary amount since the first Yakr discussion, mate. The next major milestone is no longer "add more functionality." It is getting the P0 work fully closed, correcting the capability authorisation model, then producing a precise authenticated pairing transcript that an external cryptographer can review.
