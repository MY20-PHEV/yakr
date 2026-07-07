# Yakr: A Decentralised, Social-Relay, Post-Quantum Messaging Protocol

**Version:** Draft v0.1
**Status:** Conceptual whitepaper
**Protocol name:** Yakr
**Primary design goal:** Secure, decentralised, store-and-forward messaging without a central message server.

---

## 1. Abstract

Yakr is a decentralised messaging protocol designed around end-to-end encryption, social relay delivery, rotating multi-hop message paths, and hybrid post-quantum cryptography.

Unlike conventional centralised messengers, Yakr does not require all messages to pass through a single provider-operated server. Unlike pure peer-to-peer messengers, Yakr does not assume that every user device is always online, directly reachable, or capable of accepting inbound network connections. Instead, Yakr uses a **friend-relay store-and-forward model**, where a user's trusted contact network can temporarily hold unreadable encrypted message blobs for offline recipients.

Messages are encrypted so that only the intended recipient can read them. Relays do not need to know the sender, the recipient, or the message contents. To reduce metadata leakage, Yakr uses opaque mailbox tags, rotating relay paths, two-hop or multi-hop onion-wrapped delivery, padded message blobs, short expiry windows, and per-contact delivery profiles.

Yakr is intended to be designed as an open protocol with a reference product implementation. Its core purpose is to offer a practical alternative to both centralised messaging infrastructure and fragile pure-P2P delivery systems.

---

## 2. Motivation

Modern secure messengers have made strong end-to-end encryption widely available. However, most mainstream messaging systems still depend on central infrastructure for message delivery, account discovery, push notification coordination, abuse control, and metadata management.

This creates several problems:

1. **Central availability dependency**
   If the provider's infrastructure is unavailable, blocked, degraded, or discontinued, users lose messaging capability.

2. **Provider-level metadata exposure**
   Even when message contents are encrypted, the service may observe metadata such as account identifiers, message timing, IP addresses, contact discovery patterns, device tokens, and delivery events.

3. **Platform lock-in**
   Users are typically bound to one provider's client, account system, server network, and policies.

4. **Censorship risk**
   A central service presents a relatively obvious target for blocking, throttling, legal pressure, or infrastructure disruption.

5. **Offline delivery problem in pure P2P systems**
   Pure P2P systems work well when both peers are online and reachable. Mobile devices, however, are frequently asleep, behind NAT, behind carrier-grade NAT, behind corporate firewalls, or constrained by iOS/Android background limitations.

Yakr attempts to occupy the middle ground:

```text
Not centralised:
  No single message server is required.

Not pure P2P:
  Users do not need to be simultaneously online.

Not blockchain-based:
  No global permanent ledger of messages is required.

Not federation-first:
  No homeserver is required for each user.

Instead:
  Messages are carried opportunistically through a user's trusted social relay cloud.
```

---

## 3. Design Philosophy

Yakr is based on several guiding ideas.

### 3.1 Servers should be replaceable, not trusted

Yakr does not assume that all relays are honest. Relays may be offline, curious, slow, compromised, or selective. They should not be trusted with message contents or long-term identity information.

A relay's job is intentionally boring:

```text
Receive opaque encrypted blobs.
Store them temporarily.
Forward them if instructed.
Return them to holders of valid opaque mailbox tokens.
Delete them after expiry or receipt.
```

Relays should not need to know:

```text
Who sent the message.
Who the message is for.
What the message says.
Whether a blob is a chat message, receipt, profile update, or dummy traffic.
```

### 3.2 Direct P2P is an optimisation, not the foundation

Yakr should attempt direct peer-to-peer delivery when possible. However, it must not depend on direct P2P reachability.

Direct P2P can fail because of:

```text
NAT
Carrier-grade NAT
Firewalls
Enterprise networks
Hotel/campsite Wi-Fi
Mobile network restrictions
Device sleep
iOS background limits
Offline recipients
```

Therefore, Yakr treats direct delivery as the fastest path, while friend-relay store-and-forward is the reliability path.

### 3.3 Social relays are more practical than global random storage

A public global DHT can help with discovery, but it is poorly suited as the primary storage layer for private messaging. Public writable storage invites spam, abuse, denial-of-service, and metadata leakage.

Yakr instead allows users to nominate some of their own contacts or devices as temporary relays. This creates a socially bounded storage model.

Example:

```text
Alice trusts Charlie, Dennis, Ellis, and Fred as temporary relays.

Alice sends Bob an encrypted message.

The message may be routed through one or more of Alice's relays and one or more of Bob's relays.

No relay can read it.
No relay should know the full sender-recipient relationship.
```

### 3.4 The protocol should minimise global identifiers

Yakr should avoid global usernames, phone numbers, account IDs, and public searchable directories as core protocol requirements.

Initial contact should occur by invitation:

```text
QR code
Invite link
AirDrop
WhatsApp
Telegram
SMS
Email
NFC
Local LAN exchange
```

The bootstrap channel does not need to be private forever. It only needs to carry an invitation that enables Alice and Bob to establish their own secure Yakr relationship.

This approach is inspired by privacy-preserving systems that avoid global user identifiers. SimpleX, for example, describes itself as using no identifiers assigned to users, not even phone numbers or random user IDs.

### 3.5 Post-quantum resistance should be built in early

Yakr should be designed from the beginning with hybrid post-quantum cryptography. NIST finalised its first post-quantum cryptography standards in August 2024, including ML-KEM for key establishment, ML-DSA for digital signatures, and SLH-DSA for stateless hash-based signatures.

Yakr should not rely on post-quantum crypto alone. The recommended model is hybrid:

```text
Classical cryptography + post-quantum cryptography
```

This provides defence in depth:

```text
If future quantum computers break elliptic-curve cryptography:
  the post-quantum layer still protects the session.

If a post-quantum algorithm later has a weakness:
  the classical layer still protects against normal attackers today.
```

---

## 4. Non-Goals

Yakr is not intended to be the following:

### 4.1 Not a blockchain messenger

Yakr does not require a global blockchain, consensus layer, token, mining, staking, or permanent ledger of messages.

Blockchain systems are good for public agreement about shared state. Messaging needs private delivery, metadata minimisation, deletion, expiry, and offline retrieval. A permanent shared ledger is usually the wrong default for private chat.

### 4.2 Not a general anonymous network

Yakr can borrow ideas from onion routing and mixnets, but it is not initially designed to replace Tor, I2P, Nym, or similar systems.

The first target is practical decentralised messaging with improved metadata resistance, not perfect anonymity against a global network observer.

### 4.3 Not a public social network

Yakr is designed for private messaging and small trusted groups. Public broadcast, large communities, discovery feeds, usernames, and moderation systems are outside the initial protocol scope.

### 4.4 Not dependent on one official app

The long-term goal is an open protocol with interoperable clients and relays. The first product should validate the protocol, not become the protocol.

---

## 5. System Overview

Yakr consists of five major layers:

```text
Layer 1: Identity
  User identity keys, device keys, contact pairing.

Layer 2: Session Security
  Hybrid post-quantum key agreement, ratchets, message encryption.

Layer 3: Blob Transport
  Opaque encrypted packets, mailbox tags, receipts, expiry.

Layer 4: Relay Mesh
  Friend relays, two-hop routing, path rotation, store-and-forward.

Layer 5: App Semantics
  Chat messages, attachments, read receipts, groups, profiles.
```

A simplified message flow:

```text
Alice wants to send Bob a message.

1. Alice encrypts the message for Bob.

2. Alice wraps it in an opaque blob.

3. Alice selects a fresh route:
   Alice-side entry relay → Bob-side mailbox relay.

4. Alice onion-wraps the relay instructions.

5. Alice sends the packet to the entry relay.

6. Entry relay forwards to the mailbox relay.

7. Mailbox relay stores the opaque blob under an opaque mailbox tag.

8. Bob later fetches from his mailbox relay.

9. Bob decrypts the blob locally.

10. Bob sends a receipt back using a similarly private path.
```

---

## 6. Actors

### 6.1 User

A human participant, such as Alice or Bob.

A user may have multiple devices:

```text
phone
tablet
laptop
desktop
home server
old Android relay device
```

### 6.2 Device

A physical or virtual endpoint belonging to a user.

Each device has its own device key material. Devices are linked to a user identity through explicit pairing.

### 6.3 Contact

A pairwise relationship between two users.

Yakr contacts are established by invitation, not global lookup.

### 6.4 Relay

A relay is a device or service willing to temporarily store or forward encrypted blobs.

A relay may be:

```text
a friend's phone
a user's own laptop
a user's home server
a small VPS
a community relay
a public relay
a family relay device
```

Relays are not trusted with plaintext.

### 6.5 Entry Relay

The first relay in a multi-hop path.

It may know that a certain client submitted traffic, but it should not know the final recipient.

### 6.6 Mailbox Relay

The relay that temporarily stores a blob until the recipient retrieves it.

It may know that some client later fetched a matching token or bucket, but it should not know the original sender.

### 6.7 Bootstrap Channel

Any existing communication method used to deliver a Yakr invite.

Examples:

```text
QR code
WhatsApp
Telegram
Signal
SMS
Email
NFC
AirDrop
```

The bootstrap channel is only used to begin contact establishment.

---

## 7. Identity Model

Yakr should avoid a single global account identifier.

A user has a long-term identity keypair, but this key should not be casually exposed to every relay or global discovery service.

### 7.1 User Identity Key

Each Yakr user has a long-term identity keypair.

Recommended initial design:

```text
Classical identity:
  Ed25519 or equivalent signature key

Post-quantum identity:
  ML-DSA key, optional in early versions but planned for durable identity proofs
```

ML-DSA is NIST's standardised module-lattice-based digital signature algorithm.

### 7.2 Device Keys

Each device has its own device keypair.

A user identity may authorise multiple device keys:

```text
Alice identity
  ├── Alice iPhone
  ├── Alice MacBook
  └── Alice home relay
```

Device linking must be explicit and visible to the user.

### 7.3 Pairwise Contact State

When Alice and Bob become contacts, their clients create pairwise state:

```text
Alice identity key
Bob identity key
Alice device keys
Bob device keys
shared secret material
mailbox tag derivation keys
delivery profile state
relay descriptor cache
sequence numbers
receipt state
ratchet state
```

This state is local-first. It should not require storage on any central server.

### 7.4 Pairwise Pseudonyms

Yakr should support pairwise or per-relay pseudonyms.

Alice should not necessarily use the same public relay identity with every relay or every contact.

Example:

```text
Alice main identity:
  alice_identity_pub

Alice as seen by Relay X:
  relay_client_pub_91f...

Alice as seen by Relay Y:
  relay_client_pub_42a...
```

This reduces correlation across relays.

---

## 8. Initial Contact and Invitations

Yakr initial contact happens by invitation.

Alice creates an invite and gives it to Bob through any channel.

The invite may be encoded as:

```text
QR code
yakr://invite/<encoded-bundle>
https://yakr.example/invite/<encoded-bundle>
NFC payload
file attachment
plain text block
```

### 8.1 Invite Bundle

A Yakr invite bundle should contain:

```text
protocol version
Alice identity public key
one-time invite secret
temporary rendezvous topic
temporary relay descriptors
expiry time
capability flags
signature by Alice
```

Conceptual example:

```json
{
  "protocol": "yakr-v0",
  "alice_identity_key": "A_pub_identity_key",
  "one_time_invite_secret": "random_256bit_secret",
  "rendezvous_topic": "hash(invite_secret)",
  "expires": "2026-07-07T12:00:00Z",
  "transport_hints": [
    "dht:topic_hash",
    "relay:opaque_relay_descriptor_1",
    "relay:opaque_relay_descriptor_2",
    "lan:bonjour_service_name"
  ],
  "capabilities": [
    "direct_p2p",
    "friend_relay",
    "store_forward",
    "hybrid_pq"
  ],
  "signature": "signed_by_alice_identity_key"
}
```

In a real implementation, this should be compact binary, not JSON.

### 8.2 Invite Flow

```text
1. Alice opens Yakr and taps "Add contact".

2. Alice's client generates:
   - one-time invite secret
   - rendezvous topic
   - temporary mailbox token
   - short-lived relay descriptors
   - expiry timestamp

3. Alice sends or shows the invite.

4. Bob opens the invite.

5. Bob's client attempts:
   - LAN discovery if nearby
   - DHT/rendezvous discovery
   - direct P2P hole punching
   - temporary relay mailbox contact

6. Alice and Bob perform authenticated key agreement.

7. Alice and Bob exchange delivery profiles.

8. The invite is marked consumed.

9. Future communication uses Yakr directly.
```

### 8.3 Bootstrap Trust

If Alice sends Bob an invite over WhatsApp or Telegram, the security of first contact depends partly on Bob trusting that channel to represent Alice.

To reduce risk, Yakr should support safety-code verification:

```text
Alice sees:
  Safety code: 4812 1093 8820

Bob sees:
  Safety code: 4812 1093 8820
```

Users may verify this in person, by voice, or through a second channel.

---

## 9. Delivery Profiles

After Alice and Bob pair, they exchange delivery profiles.

A delivery profile tells the other client how to reach the user when direct contact fails.

It should not reveal a plain-text address book.

Instead, it should contain opaque relay descriptors.

### 9.1 Delivery Profile Contents

A delivery profile may contain:

```text
profile version
validity period
supported protocol versions
direct transport hints
relay descriptors
mailbox token derivation parameters
preferred blob size classes
maximum accepted blob size
expiry policy
receipt policy
signature
```

Conceptual example:

```json
{
  "profile_version": 3,
  "valid_from": "2026-07-07T10:00:00Z",
  "valid_until": "2026-07-14T10:00:00Z",
  "direct_hints": [
    "dht:rotating_topic",
    "lan:service_name"
  ],
  "relay_descriptors": [
    {
      "relay_key": "opaque_relay_public_key",
      "transport": ["hyperswarm", "https", "tor"],
      "mailbox_policy": "small",
      "expires": "2026-07-09T10:00:00Z"
    }
  ],
  "blob_classes": [4096, 32768, 262144],
  "signature": "signed_by_owner_device"
}
```

### 9.2 Relay Descriptor Privacy

Relay descriptors should not expose:

```text
real contact names
phone numbers
email addresses
stable human-readable IDs
unnecessary IP addresses
```

A relay descriptor should be enough for software to attempt delivery, but not enough for the user or relay to learn the owner's full social graph.

### 9.3 Profile Refresh

Whenever Alice and Bob connect directly, they refresh:

```text
delivery profiles
relay descriptors
device lists
receipt state
ratchet state
supported capabilities
revocations
```

Profiles should expire. Stale profiles may still be tried, but clients should treat them as unreliable.

---

## 10. Message Object Model

Yakr messages are transported as encrypted blobs.

A relay should not know whether a blob contains:

```text
chat text
attachment chunk
receipt
profile update
key update
dummy traffic
```

### 10.1 Inner Message

The inner message is visible only to the recipient.

It may contain:

```text
conversation ID
sender identity
sender device ID
message sequence number
timestamp
message type
payload
attachment references
reply references
signature or MAC
```

Example:

```json
{
  "conversation": "pairwise_ab",
  "sender": "Alice",
  "device": "Alice_iPhone",
  "seq": 104,
  "type": "text",
  "body": "hello Bob",
  "created_at": "2026-07-07T10:04:21Z"
}
```

This is encrypted before leaving Alice's device.

### 10.2 Outer Blob

The outer blob is what relays see.

It should look like:

```text
blob_id
mailbox_tag or bucket tag
expiry
size class
ciphertext
optional routing layer
```

It must not contain plain sender or recipient identifiers.

### 10.3 Message IDs

Message IDs should be derived from ciphertext or authenticated content:

```text
message_id = hash(version || ciphertext || context)
```

This allows deduplication without exposing content.

### 10.4 Expiry

Every relay-stored blob should have an expiry.

Example policy:

```text
small text messages:
  keep for 7 days

large attachments:
  keep for 24–72 hours

receipts:
  keep for 7 days

dummy traffic:
  keep for short random intervals
```

---

## 11. Mailbox Tags

Mailbox tags allow Bob to retrieve messages without the relay knowing they are for Bob.

When Alice and Bob pair, they derive shared mailbox secrets.

For each epoch:

```text
mailbox_tag = HMAC(mailbox_secret, direction || epoch || slot)
```

Example:

```text
shared_secret_AB
  ↓
mailbox_secret_A_to_B
  ↓
tag for 2026-07-07 10:00
```

Alice stores a blob under that tag.

Bob independently calculates the same tag and asks relays for matching blobs.

### 11.1 Direction Separation

Alice-to-Bob and Bob-to-Alice tags must be separate:

```text
mailbox_secret_A_to_B
mailbox_secret_B_to_A
```

This prevents reflection and cross-direction confusion.

### 11.2 Epochs

Tags should rotate by time period or message slot.

Example:

```text
epoch length: 5 minutes
or
epoch length: 1 hour
or
message slot counter
```

Short epochs improve privacy but increase polling overhead.

### 11.3 Batch Fetching

For stronger privacy, Bob should not always ask for exactly one known tag.

Instead, Bob may:

```text
request several possible tags
fetch a bucket of recent blobs
download decoy blobs
poll on a fixed schedule
```

This reduces timing correlation.

---

## 12. Relay Model

A Yakr relay temporarily stores and forwards encrypted blobs.

Relays may be operated by:

```text
contacts
users themselves
community groups
public operators
paid providers
open-source volunteers
```

### 12.1 Relay Responsibilities

A relay should:

```text
accept only validly formed packets
enforce per-client storage limits
enforce rate limits
honour expiry
deduplicate blobs
forward packets when instructed
store mailbox blobs temporarily
delete blobs after expiry or receipt
avoid logging unnecessary metadata
```

### 12.2 Relay Non-Responsibilities

A relay should not need to:

```text
know message contents
know sender identity
know recipient identity
maintain a global user directory
perform contact discovery
interpret chat semantics
moderate plaintext
retain long-term history
```

### 12.3 Relay Abuse Limits

Relays must protect themselves.

Minimum relay policies:

```text
maximum storage per authorised client
maximum blob size
maximum blob count per time window
maximum forwarding rate
maximum expiry duration
accepted protocol versions
proof-of-work or token requirement if needed
```

### 12.4 Relay Consent

Contacts should explicitly opt in to acting as relays.

A user may choose:

```text
Do not relay for anyone.
Relay only for favourites.
Relay for contacts.
Relay for contacts-of-contacts.
Relay only on Wi-Fi and charging.
Relay only up to 50 MB.
Relay only for 24-hour expiry messages.
```

---

## 13. Two-Hop Delivery

Yakr's default privacy-preserving store-and-forward route should require at least two relays where possible.

Example route:

```text
Alice
  ↓
Entry relay
  ↓
Mailbox relay
  ↓
Bob
```

### 13.1 Why Two Hops?

With one relay:

```text
Relay may observe:
  Alice uploaded a blob.
  Bob later fetched a blob.
  Timing and size match.
```

With two relays:

```text
Entry relay sees:
  Alice or an Alice-side pseudonym submitted a packet.
  It was forwarded somewhere else.

Mailbox relay sees:
  A relay submitted a packet.
  Bob or a Bob-side pseudonym later fetched a matching blob.

No single honest relay sees both the original sender and final recipient.
```

### 13.2 Onion Wrapping

Alice onion-wraps relay instructions:

```text
Outer layer:
  readable by entry relay
  instruction: forward to mailbox relay

Middle layer:
  readable by mailbox relay
  instruction: store under opaque tag

Inner layer:
  readable only by Bob
  actual message
```

Conceptually:

```text
packet_to_entry =
  encrypt_for_entry_relay(
    next_hop = mailbox_relay,
    payload = encrypt_for_mailbox_relay(
      mailbox_tag = tag_X,
      blob = encrypt_for_bob(message)
    )
  )
```

### 13.3 Relay Knowledge

Entry relay should not know:

```text
message content
final recipient
mailbox tag meaning
whether payload is text, receipt, or attachment
```

Mailbox relay should not know:

```text
original sender
message content
whether Bob is the human recipient
relationship between Alice and Bob
```

---

## 14. Path Rotation

Yakr should avoid using the same relay path repeatedly.

For each message, Alice should select a fresh route.

Example:

```text
Message 1:
  Alice → Charlie → Dennis → Bob

Message 2:
  Alice → Ellis → Fred → Bob

Message 3:
  Alice → Dennis → Charlie → Bob

Message 4:
  Alice → Fred → Ellis → Bob
```

### 14.1 Route Selection

Route selection should consider:

```text
relay availability
relay trust level
relay storage capacity
recent successful delivery
battery/network constraints
avoidance of recent path reuse
randomness
geographic/network diversity if available
```

### 14.2 Deterministic But Private Selection

Clients may derive route randomness from conversation secrets:

```text
route_seed = HKDF(conversation_secret, message_id || "route")
```

Then choose relays using weighted randomness.

This provides unpredictability to outsiders while allowing local reproducibility for retry decisions.

### 14.3 Path Reuse Limits

A client should avoid:

```text
same entry relay repeatedly
same mailbox relay repeatedly
same entry-mailbox pair repeatedly
same path for all messages in a conversation
```

### 14.4 Multi-Path Attachments

For large messages or attachments, Yakr may split content into chunks.

Each chunk may take a different route:

```text
chunk 1 → relay path A
chunk 2 → relay path B
chunk 3 → relay path C
```

Future versions may use erasure coding:

```text
Create 6 chunks.
Recipient needs any 4 to reconstruct.
Send chunks over different paths.
```

This improves reliability and metadata resistance, at the cost of complexity and bandwidth.

---

## 15. Timing, Padding, and Cover Traffic

Encryption hides content, but not necessarily timing and size.

Yakr should therefore support metadata-reduction techniques.

### 15.1 Padding

Blobs should be padded to fixed size classes.

Example:

```text
4 KB
32 KB
256 KB
1 MB
```

A 300-byte message may be padded to 4 KB. A 12 KB message may be padded to 32 KB.

### 15.2 Random Delays

Relays may delay forwarding slightly.

Example:

```text
delay = random between 5 and 90 seconds
```

Delay makes timing correlation harder.

Different message classes may have different delay policies:

```text
urgent text:
  low delay

normal text:
  moderate delay

bulk attachment:
  larger delay allowed

high privacy mode:
  batch and delay more aggressively
```

### 15.3 Batch Fetching

Bob should not fetch only when he expects a message.

Instead, Bob may poll relays periodically:

```text
every 5 minutes
every 15 minutes
when app wakes
when push notification arrives
when direct network changes
```

Polling should fetch multiple candidate tags or buckets.

### 15.4 Dummy Traffic

High-privacy mode may generate dummy blobs.

Dummy traffic helps obscure:

```text
whether a real message was sent
how often a user communicates
which relay paths correspond to real conversations
```

However, dummy traffic costs battery, bandwidth, and storage.

---

## 16. Cryptographic Design

Yakr should use established primitives and avoid custom cryptography.

### 16.1 Hybrid Key Agreement

For initial contact and periodic rekeying, Yakr should use hybrid key agreement:

```text
Classical:
  X25519

Post-quantum:
  ML-KEM-768 or selected ML-KEM parameter set

Combiner:
  HKDF over both shared secrets
```

NIST's FIPS 203 specifies ML-KEM, a module-lattice-based key encapsulation mechanism.

Conceptually:

```text
x_secret = X25519(Alice_private, Bob_public)
pq_secret = ML-KEM shared secret

master_secret = HKDF(
  input = x_secret || pq_secret,
  salt = transcript_hash,
  info = "Yakr hybrid session v0"
)
```

Signal's PQXDH protocol is a relevant reference point because it combines post-quantum key establishment with Signal-style authenticated key agreement to protect against future quantum attacks.

Apple's PQ3 for iMessage is also relevant because it combines post-quantum initial key establishment with ongoing ratchets for self-healing.

### 16.2 Message Encryption

Normal message encryption should use symmetric AEAD encryption.

Candidate primitives:

```text
XChaCha20-Poly1305
AES-256-GCM
AES-256-GCM-SIV
```

The protocol should specify one mandatory-to-implement AEAD to ensure interoperability.

### 16.3 Ratcheting

Yakr should use a ratchet for forward secrecy and post-compromise recovery.

Initial design:

```text
classical double ratchet style construction
periodic post-quantum rekey events
symmetric-key message ratchets
device-specific sending chains
```

Post-quantum operations may be too heavy for every message in early mobile versions, so Yakr should use PQ key establishment periodically and symmetric ratchets for ordinary messages.

### 16.4 Signatures

Normal messages should not necessarily carry large post-quantum signatures.

Instead:

```text
Normal messages:
  authenticated through session keys / MACs.

Important durable objects:
  invite bundles
  identity proofs
  device linking records
  relay descriptors
  delivery profiles
  revocation records

These may use:
  Ed25519 + ML-DSA hybrid signatures.
```

ML-DSA is NIST's standardised module-lattice-based digital signature algorithm. SLH-DSA provides a stateless hash-based signature option.

### 16.5 Key Separation

Yakr must derive separate keys for separate purposes:

```text
message encryption
mailbox tag derivation
receipt authentication
relay packet wrapping
profile encryption
attachment encryption
dummy traffic generation
device sync
```

All derived keys should use domain separation strings.

Example:

```text
HKDF(master_secret, info="yakr/message-key/v0")
HKDF(master_secret, info="yakr/mailbox-tag/v0")
HKDF(master_secret, info="yakr/receipt-key/v0")
HKDF(master_secret, info="yakr/relay-wrap/v0")
```

---

## 17. Direct P2P Delivery

Yakr should try direct delivery before relay delivery when possible.

Direct options:

```text
LAN discovery
DHT rendezvous
UDP hole punching
IPv6 direct
manual endpoint hints
Tor onion service
WebRTC-style ICE
```

However, Yakr must not depend on direct reachability.

### 17.1 Direct Attempt Flow

```text
1. Alice wants to send Bob a message.

2. Alice checks Bob's latest delivery profile.

3. Alice attempts direct contact:
   - LAN
   - known endpoint
   - DHT rendezvous
   - hole punch

4. If direct succeeds:
   deliver immediately.

5. If direct fails or times out:
   use relay path.
```

### 17.2 Direct Delivery Privacy

Direct delivery may reveal Alice and Bob's network addresses to each other, which is expected for direct communication.

Users may disable direct P2P for higher privacy.

---

## 18. Offline Delivery

Offline delivery is Yakr's central feature.

### 18.1 Alice Sends While Bob Is Offline

```text
1. Alice encrypts message for Bob.

2. Alice selects an entry relay and mailbox relay.

3. Alice sends onion-wrapped packet to entry relay.

4. Entry relay forwards to mailbox relay.

5. Mailbox relay stores blob under opaque mailbox tag.

6. Alice keeps a local pending copy until receipt.
```

### 18.2 Bob Comes Online Later

```text
1. Bob calculates mailbox tags for missed epochs.

2. Bob contacts mailbox relays from his profile.

3. Bob fetches matching blobs or recent buckets.

4. Bob attempts local decryption.

5. Bob verifies sender/authentication inside decrypted content.

6. Bob stores the message locally.

7. Bob sends receipt back through Yakr.
```

### 18.3 Alice Receives Receipt

```text
1. Alice fetches receipt.

2. Alice marks message as delivered.

3. Alice stops retrying.

4. Relays may delete the delivered blob.
```

---

## 19. Receipts

Receipts are themselves encrypted Yakr messages.

Receipt types:

```text
accepted by relay
stored by mailbox relay
fetched by recipient device
decrypted by recipient device
displayed
read
```

For privacy, Yakr should allow users to disable read receipts.

A minimal receipt:

```text
message_id
receipt_type
recipient_device
timestamp
authentication tag
```

Receipts should use the same relay privacy protections as messages.

---

## 20. Groups

Group messaging should not be part of the earliest implementation unless necessary.

However, the protocol should be designed with groups in mind.

### 20.1 Small Groups

For small groups, Yakr can send individually encrypted messages to each member.

Example:

```text
Alice sends to group of 5.

Client creates:
  message encrypted for Bob
  message encrypted for Charlie
  message encrypted for Dennis
  message encrypted for Ellis
  message encrypted for Fred
```

This is simple but inefficient.

### 20.2 Group Sender Keys

Later versions may use group sender keys or MLS-like group key management.

The IETF Messaging Layer Security approach may be worth studying for future group support, but Yakr's social relay model adds unique delivery constraints.

### 20.3 Group Relay Strategy

Group messages may be distributed through:

```text
sender-side relays
recipient-side mailbox relays
group-designated relays
multi-path chunking
```

Group metadata is much harder to hide than pairwise metadata.

---

## 21. Attachments

Attachments should be chunked, encrypted, content-addressed, and distributed across relays.

### 21.1 Attachment Flow

```text
1. Alice encrypts attachment with random attachment key.

2. Alice splits encrypted attachment into chunks.

3. Each chunk gets a content hash.

4. Chunks are sent over rotated relay paths.

5. Bob receives message containing:
   - attachment manifest
   - chunk hashes
   - decryption key
   - size
   - expiry
```

### 21.2 Erasure Coding

Future versions may use erasure coding:

```text
Original attachment split into N recoverable chunks.
Bob only needs K of N chunks.
```

This helps when some relay paths fail.

---

## 22. Threat Model

Yakr aims to protect against:

```text
curious relays
compromised relays
passive network observers
message capture for future quantum attack
single relay metadata inference
temporary device compromise with recovery
provider infrastructure dependency
censorship of a single server
offline recipient unavailability
```

Yakr does not fully protect against:

```text
global passive adversary observing all network traffic
all relays colluding
both sender and recipient devices compromised
malicious recipient screenshotting or forwarding messages
social engineering
traffic analysis with unlimited observation
device OS compromise
push notification provider metadata
```

### 22.1 Relay Collusion

If entry relay and mailbox relay collude, they may correlate timing and size.

Mitigations:

```text
path rotation
padding
random delay
batching
dummy traffic
multi-path chunking
larger relay set
```

### 22.2 Device Compromise

If Alice's device is compromised, an attacker may read Alice's local messages and keys.

Mitigations:

```text
device-level secure storage
ratchet recovery
device revocation
short-lived session keys
remote device removal
local database encryption
```

### 22.3 Harvest Now, Decrypt Later

Attackers may record encrypted traffic today and attempt to decrypt it in the future using quantum computers.

Mitigation:

```text
hybrid post-quantum key agreement
periodic PQ rekeying
symmetric ratchets
limited relay retention
```

---

## 23. Comparison With Existing Models

### 23.1 Centralised Messengers

Examples:

```text
WhatsApp
Signal
Telegram normal cloud chats
iMessage
```

Advantages:

```text
high reliability
good UX
push notifications
easy contact discovery
fast delivery
mature clients
```

Disadvantages:

```text
central infrastructure dependency
provider-visible metadata
account systems
platform lock-in
service-level censorship target
```

Yakr trades some reliability and convenience for decentralised delivery and relay-level metadata reduction.

### 23.2 Federated Messengers

Example:

```text
Matrix
XMPP
```

Advantages:

```text
open networks
multiple servers
public interoperability
communities
bridges
```

Disadvantages:

```text
server-heavy
metadata visible to homeservers
administration burden
federation complexity
public identity surfaces
```

Yakr does not require homeservers. Delivery is local-first and relay-assisted.

### 23.3 Pure P2P Messengers

Example design pattern:

```text
Alice directly connects to Bob.
If Bob is offline, delivery waits.
```

Advantages:

```text
no server needed when peers are online
simple trust model
good direct privacy
```

Disadvantages:

```text
offline delivery is hard
NAT traversal is unreliable
mobile background limitations
```

Yakr adds social relay store-and-forward to solve offline delivery.

### 23.4 Relay Queue Messengers

SimpleX is an important related design because it avoids user identifiers and uses message queues rather than normal global account IDs.

Yakr differs by making friend/social relays and rotating multi-hop social delivery a core design element.

---

## 24. Product Strategy

Yakr should be developed as a protocol-led product.

### 24.1 Protocol First, Product Early

The protocol defines:

```text
identity
invites
delivery profiles
blob formats
relay behaviour
crypto
routing
receipts
```

The product proves that the protocol can actually work for normal users.

### 24.2 First Product Scope

The first Yakr product should be narrow:

```text
one-to-one messaging
QR/link invites
text messages
delivery receipts
friend relay opt-in
two-hop delivery
path rotation
Android first if practical
desktop/CLI prototype before mobile
```

Avoid initially:

```text
voice calls
video calls
large groups
public discovery
stickers
bots
large media libraries
cloud backup
multi-account business features
```

### 24.3 Reference Implementation

Recommended components:

```text
yakr-core:
  protocol and crypto library

yakr-relay:
  relay daemon

yakr-cli:
  command-line prototype

yakr-mobile:
  Android/iOS client

yakr-spec:
  open protocol documentation
```

---

## 25. Implementation Roadmap

### Phase 0: Protocol Sketch

Deliverables:

```text
whitepaper
message flow diagrams
threat model
primitive selection
terminology
```

### Phase 1: CLI Proof of Concept

Goal:

```text
Alice, Bob, Charlie, Dennis simulated locally.
```

Must demonstrate:

```text
Alice sends encrypted message to Bob.
Bob is offline.
Charlie and Dennis relay/store.
Alice goes offline.
Bob comes online.
Bob retrieves and decrypts message.
```

### Phase 2: Two-Hop Onion Relay

Add:

```text
entry relay
mailbox relay
onion-wrapped instructions
relay-local storage
expiry
receipts
```

### Phase 3: Path Rotation

Add:

```text
relay scoring
random route selection
no repeated path
per-message route change
```

### Phase 4: Hybrid Post-Quantum Key Agreement

Add:

```text
X25519 + ML-KEM
HKDF combiner
versioned key formats
session transcript binding
```

### Phase 5: Delivery Profiles

Add:

```text
profile exchange
relay descriptors
profile expiry
profile refresh
opaque mailbox tags
```

### Phase 6: Mobile Prototype

Start with Android because background networking and sideloading are easier than iOS.

Add:

```text
local database
notifications
battery-aware relay mode
Wi-Fi-only relay option
QR invite
basic UI
```

### Phase 7: iOS Feasibility

iOS constraints:

```text
background execution limits
push notification dependence
App Store policy
no arbitrary background daemon
limited P2P persistence
```

iOS may need:

```text
APNS wake notifications
reduced relay functionality
foreground-heavy operation
user-owned relay devices for better reliability
```

### Phase 8: Public Protocol Draft

Publish:

```text
Yakr Protocol v0.1
test vectors
reference packet formats
interop tests
security analysis
```

---

## 26. Open Questions

### 26.1 How much relay metadata leakage is acceptable?

Yakr can reduce metadata, but perfect metadata privacy is expensive.

Modes may be needed:

```text
fast mode
balanced mode
high privacy mode
disaster/off-grid mode
```

### 26.2 Should Yakr use a public DHT?

A DHT may help with:

```text
temporary invite rendezvous
peer discovery
relay discovery
direct P2P bootstrap
```

But DHTs should not be primary message storage.

### 26.3 How should relays be incentivised?

For friend relays, social trust may be enough.

For public relays, possible models:

```text
voluntary
paid
community-operated
proof-of-work gated
storage-credit based
```

### 26.4 How should Yakr handle spam?

Possible controls:

```text
invite-only contact establishment
relay accepts only known signed clients
per-contact storage limits
proof-of-work for unknown requests
no global inbox
no public searchable user IDs
```

### 26.5 How should push notifications work?

On mobile platforms, push is difficult to avoid.

Possible options:

```text
no push, delayed polling only
privacy-preserving wake notifications
self-hosted push bridge
platform push with minimal metadata
user-owned always-on relay device
```

### 26.6 How should multi-device sync work?

Multi-device support requires careful key management.

Options:

```text
each device is an independent recipient
primary device authorises secondary devices
delivery profiles list device-specific mailbox tags
encrypted local history transfer
no automatic cloud backup
```

---

## 27. Security Principles

Yakr implementations should follow these rules:

```text
Do not invent new cryptographic primitives.

Use audited libraries where possible.

Use hybrid classical + post-quantum key agreement.

Separate keys by purpose.

Avoid global identifiers.

Avoid plaintext sender/recipient metadata in relay packets.

Use expiry for all relay-stored blobs.

Rotate paths.

Pad blobs.

Batch where possible.

Make relay participation explicit.

Treat direct P2P as optional.

Assume relays are curious.

Assume some relays are offline.

Assume some relays collude.

Assume mobile devices sleep.

Assume network conditions are hostile.
```

---

## 28. Summary

Yakr is a proposed decentralised messaging protocol based on the idea that messages can be securely carried by a user's trusted social relay network rather than by a central provider.

Its core properties are:

```text
End-to-end encrypted messages
No central message server required
Friend/social relay store-and-forward delivery
Direct P2P when available
Offline delivery through relays
Opaque mailbox tags
Two-hop onion-wrapped relay paths
Per-message path rotation
Relay-visible metadata reduction
Invite-based contact establishment
No required phone numbers or global usernames
Hybrid post-quantum cryptography
Local-first message history
Open protocol direction
```

Yakr's central insight is that a messenger does not need to choose between fragile pure P2P and centralised server delivery. A user's own social graph can become a decentralised, privacy-preserving delivery fabric.

The result is not perfectly anonymous, not infrastructure-free, and not as simple as centralised messaging. But it offers a realistic and technically interesting path toward private messaging that remains useful when users are offline, behind NAT, or unwilling to rely on a single provider-operated server.

Yakr should therefore be developed as a protocol-led product: first as a working CLI proof of concept, then as a reference implementation, then as a mobile product, and eventually as an open interoperable protocol.
