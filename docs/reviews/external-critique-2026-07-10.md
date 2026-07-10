# External Protocol Review — 10 July 2026

**Status:** Reference (not normative)  
**Source:** Independent review following whitepaper + reference design review  
**Audience:** Project maintainers; informs P0–P3 backlog prioritisation  
**Follow-up:** [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md), [delivery-state-machine.md](../spec/delivery-state-machine.md)

---

Ellis, honestly: this has crossed the line from "interesting messenger idea" into a credible protocol project.
The strongest thing is not any individual cryptographic choice. It is that you have repeatedly forced the design to confront reality:

- phones sleep;
- mobile devices are usually not inbound-reachable;
- decentralisation still requires reachable infrastructure somewhere;
- relays reduce trust but do not magically eliminate metadata;
- direct delivery is an optimisation, not the reliability path;
- post-quantum protection does not replace classical cryptography;
- Yakr is not claiming perfect anonymity.

That intellectual honesty is rare. The whitepaper has a clear identity, and the reference design is unusually implementation-oriented rather than being a wish list.

My overall assessment would be:

- The architecture is fundamentally plausible. I do not see a fatal conceptual flaw.
- The biggest risks are now protocol-state correctness, capability privacy, downgrade resistance, mobile delivery behaviour, and several claims that are currently stronger than the documented implementation can safely support.

## What I think is genuinely strong

### 1. The social-relay concept now feels distinct

Originally, I thought Yakr risked becoming "Signal encryption over self-hosted servers." It no longer feels like that.

The rule that relay infrastructure is distributed through pairing relationships, rather than a public global relay directory, gives Yakr a recognisable model:

- Alice trusts Charlie enough to use Charlie's relay.
- Bob trusts Alice.
- Alice's signed profile permits Bob to use Charlie's relay for delivery to Alice.
- Bob does not need a separate account with Charlie.

That is quite elegant.

It creates a decentralised delivery fabric without requiring:

- a global relay registry;
- global usernames;
- public inboxes;
- a universal Yakr server fleet;
- every user to run infrastructure.

The distinction between relay operator trust and message confidentiality is also good. Charlie is trusted to offer storage and availability, but not trusted with plaintext.

### 2. You have solved the mobile reachability misconception properly

This section is excellent:

**Correctness path:** outbound POST to paired relays → recipient outbound poll

**Optimisation path:** direct when dialable

A lot of decentralised messaging proposals quietly assume phones can operate like little internet servers. You have explicitly rejected that assumption.

That decision probably saves Yakr from years of chasing unreliable NAT traversal.

### 3. The relay-less-user model is good

This is subtle but important:

Bob does not have to operate a relay just to message Alice.

Alice publishes mailboxes through her profile. Bob can deliver through those. New users can therefore participate before they understand Docker, VPSs, port forwarding, DNS, or TLS.

That makes the network much more organically adoptable than:

```text
Install Yakr
↓
Buy VPS
↓
Configure relay
↓
Now you may receive messages
```

### 4. The scope control is unusually disciplined

You have consciously postponed:

- groups;
- large attachments;
- full multi-device sync;
- public DHT discovery;
- large public communities;
- calls;
- cloud backup.

That is exactly right.

Multi-device identity sync in particular could swallow the entire project. Defining v1 as one active messaging identity per installation is a sensible simplification.

### 5. Protocol-first plus test vectors is the right direction

The separation into:

- yakr-core
- yakr-relay
- yakr-cli
- yakr-testkit

is clean.

Making the crypto and packet layer independent of network I/O is also an excellent architectural decision. It gives you a plausible future route to:

```text
Python reference implementation
          ↓
Rust production core
          ↓
same Yakr wire protocol
```

The emphasis on golden vectors and independent interoperability is exactly what an open protocol needs.

## The issues I would address first

These are not reasons to abandon anything. They are the areas I would attack before presenting Yakr as cryptographically mature.

### 1. The whitepaper and reference implementation now describe slightly different Yakrs

Your abstract says:

> "pairing-gated social relays, rotating multi-hop message paths…"

But later, the actual reference-client path is:

- single mailbox relay
- ordered relay failover

with two-hop onion delivery optional and mostly retained as a wire capability.

That is completely reasonable technically. In fact, I think defaulting to single-hop is probably the practical choice.

The problem is positioning.

At the moment a reader could come away believing rotating two-hop routing is a core property of normal Yakr delivery when it is not.

I would revise the opening description to something like:

> Yakr is a decentralised messaging protocol based on end-to-end encryption, pairing-gated social mailboxes, relay failover, and hybrid post-quantum cryptography. Deployments may optionally use multi-hop relay paths and metadata-hardening modes.

That makes the implemented foundation primary and the stronger metadata mode optional.

The summary already comes much closer to this distinction. The abstract should match it.

### 2. Relay authorisation may accidentally introduce stable relay-visible identities

Your conceptual ticket is:

```text
relay_ticket {
  relay_pubkey
  contact_id
  permissions
  expires_at
  issuer_device_signature
}
```

This worries me.

Depending on the real implementation, the relay may learn:

- a stable contact_id;
- the issuer identity or device public key;
- which authorisation tickets came from the same user;
- which mailbox operations are connected to that user.

That would undermine some of the pairwise-pseudonym benefits.

The relay should ideally see a random, relay-specific capability rather than a contact identity.

Something closer to:

```text
relay_capability {
    capability_id: random bytes
    permissions: store | fetch | forward
    quota
    expiry
    relay_binding
}
```

The capability could be issued during operator pairing, with a relay-specific authorisation key that is not Alice's normal identity key.

Then Charlie sees:

```text
capability 7ea148...
```

rather than:

```text
Alice issued a ticket for contact Bob
```

You already mention pairwise and per-relay pseudonyms in the whitepaper. I would make that a hard requirement, not an aspirational feature.

### 3. Do not put mailbox tags in a GET URL

The early API is:

```http
GET /v1/blobs/{tag}
```

Even when HTTPS is used, URL paths are commonly captured by:

- reverse-proxy access logs;
- application-server logs;
- tracing tools;
- error monitoring;
- load balancers;
- browser or HTTP tooling;
- infrastructure dashboards.

Your relay application may obey the no-tag logging policy, while nginx quietly records every mailbox tag.

I would use something like:

```http
POST /v1/fetch
Content-Type: application/cbor

{
    tags: [...]
}
```

or a binary request body.

That does not hide the tag from the relay—it cannot—but it greatly reduces accidental persistence throughout infrastructure.

The logging rule is good, but protocol design should make compliance easier rather than depending entirely on operational discipline.

### 4. The delivery semantics need a formal state machine

The documents explain the flow well in human terms, but messaging protocols tend to break in edge cases, not the happy path.

You need a normative state machine for at least:

- outbound message
- relay accepted
- relay stored
- recipient fetched
- recipient decrypted
- receipt queued
- receipt delivered
- sender acknowledged
- expired
- retrying
- abandoned

Questions that need exact answers:

- Does relay fetch delete the blob?
- What happens if Bob downloads a blob and crashes before decrypting it?
- What happens if Bob decrypts it but crashes before sending the acknowledgement?
- Can a malicious fetcher delete someone else's blob?
- Is delivery at-most-once or at-least-once?
- Can the relay return the same blob repeatedly?
- How long does Alice retain pending ciphertext?
- Is acknowledgement separate from retrieval?
- What happens when two Bob processes fetch simultaneously?
- Can an old receipt clear a newer message state?

I strongly favour:

```text
At-least-once transport
+
idempotent recipient processing
+
explicit authenticated acknowledgement
```

That means duplicates are expected and harmless.

The relay should not destroy a message merely because it was fetched. It should delete after authenticated acknowledgement or expiry.

### 5. Ratchet crash safety may be one of the hardest real problems

The documents mention persisted ratchet state and duplicate-sequence detection, but the dangerous case is:

1. Client advances sending ratchet.
2. Client encrypts message.
3. Process crashes before committing database state.
4. Client restarts with old ratchet state.
5. Same key material may be reused.

Or the reverse:

1. Database ratchet advances.
2. Process crashes before outbound message is persisted.
3. A sending key is permanently skipped.

You need transactional coupling between:

- ratchet advancement
- message encryption
- outbound queue insertion

Ideally all in one local database transaction.

Receiving has similar problems:

- decrypt
- advance receive chain
- store message
- record deduplication

must be crash-consistent.

This needs explicit treatment in the security design. A mathematically sound ratchet can still fail catastrophically if state persistence is wrong.

### 6. "Minimal in-tree double ratchet" is the part that makes me most nervous

You correctly say:

> Do not invent new cryptographic primitives.

But implementing a Double-Ratchet-style protocol is not inventing a primitive—it is still very easy to implement incorrectly.

Potential traps include:

- skipped-message-key limits;
- out-of-order delivery;
- replay handling;
- ratchet public-key validation;
- invalid-curve or malformed-key handling;
- state rollback;
- key deletion;
- concurrent sends;
- multiple outstanding receive chains;
- denial of service through huge skipped sequence numbers;
- identity binding;
- unknown-key-share attacks.

I would separate these statements:

- The cryptographic primitive choices are sensible.
- The session protocol is not yet assumed secure merely because it uses X25519, HKDF and XChaCha20-Poly1305.

The composition matters.

I would eventually want the Yakr session design reviewed independently before calling the protocol production-secure.

### 7. Post-quantum downgrade handling needs to be explicit

You support:

```text
hybrid-capable client
↕
classical-only fallback
```

That is useful for compatibility but creates a downgrade question.

Suppose both Alice and Bob support hybrid PQ, but an attacker alters capability negotiation so each believes the other only supports classical crypto.

The negotiated capability set must be:

- authenticated;
- included in the transcript hash;
- visible to the user when security changes;
- resistant to rollback.

I would specify a policy such as:

- First contact records peer capability floor.
- Once a contact has successfully used Hybrid PQ v1, future classical-only negotiation is rejected unless the user explicitly approves a security reset.

In other words, no silent downgrade after PQ has been established.

The same applies to protocol version rollback.

### 8. The ML-DSA invite may not fit your desired QR experience

ML-DSA keys and signatures are much larger than Ed25519.

If an invite includes:

- identity public key
- ML-KEM material
- ML-DSA public key
- ML-DSA signature
- relay descriptors
- TLS pins
- capabilities
- expiry
- rendezvous information

the QR may become enormous or require a very dense symbol that scans badly from another phone.

Your existing concept already has a natural solution:

```text
QR contains:
    short random one-time rendezvous secret
    relay URL
    expected bundle hash

Signed full invite bundle:
    fetched from rendezvous relay
```

The QR can remain compact while the large cryptographic material moves through the rendezvous channel.

The fetched bundle is still safe because its digest or authentication secret came through the QR.

This is worth measuring now rather than discovering it during mobile UI work.

### 9. Polling is correct, but timely mobile messaging may still depend on central infrastructure

I agree with your protocol decision:

- Polling is normative.
- Push wake is optional.

That preserves decentralised correctness.

But on a real Android or iPhone, the difference between:

- message eventually delivered

and:

- message appears within seconds

may be an FCM/APNs wake.

That is not a failure, but the product messaging must be precise.

Perhaps:

> Yakr message storage and delivery do not depend on a central Yakr platform. Optional operating-system push services may be used only as wake-up hints for lower latency.

The wake service can still see metadata such as:

- a device token;
- wake timing;
- which relay requested a wake;
- possibly frequency patterns.

You acknowledge this, which is good. I would put it closer to the main architecture because users will care.

### 10. "Relays never know who is sending or fetching" should be softened

The crypto can prevent protocol-level identity disclosure, but a relay normally sees network facts:

- source IP connected
- time of request
- TLS session
- request size
- mailbox capability/tag
- fetch timing

A self-hosted relay may also know perfectly well:

> "That residential IP belongs to Ellis."

Two hops help separate some observations but do not make them disappear.

I would consistently say:

> Relays do not receive plaintext sender or recipient identifiers and cannot decrypt message contents.

rather than:

> Relays do not know who sent or fetched anything.

The first is defensible.

The second can be false at the network layer.

Your threat-model sections already understand this; some of the higher-level prose is just more absolute than the threat model.

## Document inconsistencies I noticed

These are easy fixes but worth cleaning up.

### Missing Phase 5 heading

In the reference design, after Phase 4 exit criteria, the document goes directly into:

```text
Depends on: Phase 4
Protocol: yakr-v0.5
Status: Complete
```

but the heading:

```text
## Phase 5 — Delivery Profiles
```

appears to be missing.

That explains why the heading index jumps from Phase 4 to Phase 6.

### Roadmap numbering differs between documents

The whitepaper currently has:

- Phase 4: Hybrid PQ
- Phase 5: Delivery Profiles
- Phase 6: Mobile

The reference design has:

- Phase 4: Invites
- Phase 5: Delivery Profiles
- Phase 6: Hybrid PQ
- Phase 8: Mobile

The reference design says it refines the ordering, which explains it, but readers will still become confused.

I would make the whitepaper roadmap defer entirely to the reference design:

> The implementation phases are maintained in REFERENCE_DESIGN.md; the following is a conceptual dependency sequence only.

Or update the whitepaper to use the same phase numbers.

### TTL differs

The Phase 1 design says message blobs have a 24-hour TTL.

The whitepaper gives an example of small text messages being retained for 7 days.

Examples are not normative, but this is exactly the kind of difference implementers may copy.

I would define:

- Protocol maximum TTL
- Relay-advertised maximum
- Sender-requested TTL
- Actual relay-selected TTL

Then the implementation can choose policy without ambiguity.

### "Complete" needs qualification

Seeing:

- Phase 1–9 complete
- Phase 10 mostly complete
- Android complete
- public protocol complete
- independent interop complete

is impressive—but based on these two documents alone, I cannot verify the implementation, tests, Android artefact, independent client, or audit.

I would distinguish:

- Implementation status: complete
- Security maturity: experimental
- Protocol stability: draft
- External audit: not performed
- Production recommendation: no

That protects you from readers interpreting "complete" as "secure and production-ready."

## My proposed priority order

Before adding Tor, Meshtastic, LoRaWAN, ephemeral cloud deployment, or more transports, I would spend the next design cycle on these:

### P0 — protocol correctness

- Formal message/receipt/retry state machine.
- Transactional ratchet persistence.
- Replay, duplicate and out-of-order behaviour.
- Fetch acknowledgement and deletion semantics.
- Capability/token revocation.
- Profile rollback and replay protection.
- TLS-pin rotation and relay key compromise recovery.

### P1 — identity and authorisation privacy

- Remove stable contact_id values from relay-visible tickets.
- Use per-relay pseudonymous authorisation keys.
- Separate operator identity from relay client capability.
- Define exactly what Charlie can correlate.
- Create a relay-observer privacy table.

Something like:

| Observation | Entry relay | Mailbox relay | Network observer |
|-------------|-------------|---------------|------------------|
| Client IP | Yes | Fetcher only | Possibly |
| Mailbox tag | No in two-hop | Yes | No under TLS |
| Blob size | Yes | Yes | Approximate |
| Sender identity key | Must be no | Must be no | No |
| Recipient identity key | No | Must be no | No |
| Timing | Yes | Yes | Yes |

That table would be extremely valuable.

### P2 — cryptographic protocol review

- Produce a precise session-state specification.
- Publish complete transcript construction.
- Define downgrade prevention.
- Define key-erasure requirements.
- Define skipped-key limits.
- Add malicious-input test vectors.
- Fuzz CBOR parsers and state transitions.

### P3 — real mobile evidence

Measure on physical Android hardware:

- screen on
- screen off
- Doze
- app backgrounded
- app killed
- phone rebooted
- Wi-Fi only
- mobile data
- battery saver
- 24-hour idle

Record:

- median delivery delay
- 95th percentile delay
- battery consumption
- wake reliability
- message loss
- duplicate count

That data will tell you whether optional platform wake is merely nice or practically necessary.

## One bigger philosophical observation

The strongest version of Yakr may not be:

> "A messenger where every message takes a different two-relay onion path."

It may actually be:

> "A cryptographically private messaging protocol where the delivery infrastructure belongs to the users' social graph rather than one platform."

That is simpler and, I think, more original.

The onion routing, path diversity, padding and cover traffic then become optional privacy layers.

The core insight remains useful even with a single relay:

| System | Dependency |
|--------|------------|
| Signal | everyone depends on Signal infrastructure |
| Matrix | users depend on homeservers |
| Yakr | each social graph supplies replaceable encrypted mailboxes |

That is a clear idea people can understand.

## Bottom line

| Area | Assessment |
|------|------------|
| Core concept | Very strong |
| Architectural realism | Very strong |
| Scope discipline | Excellent |
| Mobile assumptions | Good and honest |
| Protocol identity | Now genuinely distinctive |
| Cryptographic primitives | Sensible choices |
| Cryptographic composition | Needs specialist scrutiny |
| Metadata claims | Mostly honest, occasionally overstated |
| Relay authorisation privacy | Needs deeper examination |
| Product viability | Plausible |
| Production security | Not yet something the documents alone can establish |

This is good work, Ellis. Much better than I expected when we first started discussing encrypted blobs wandering through friends' relays. The next valuable step is probably not another feature; it is to turn the security-critical flows into exact, hostile-input-resistant state machines.
