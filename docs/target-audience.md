# Target Audience and Positioning

**Status:** Draft product guidance (not normative protocol)  
**Date:** 2026-07-10  
**Related:** [whitepaper.md](../whitepaper.md), [homelab-relay.md](homelab-relay.md), [REFERENCE_DESIGN.md](REFERENCE_DESIGN.md)

## Core insight

Yakr appeals most strongly to people who dislike the idea that private communication still depends on somebody else's platform existing, behaving, and remaining available.

The natural audience is probably **broader than hardcore anonymity users** and **narrower than the general WhatsApp market**. Several overlapping groups fit that band.

---

## Audience segments

### Privacy-conscious technical users

The most immediate audience.

People who already run things like Home Assistant, Tailscale, WireGuard, Nextcloud, Matrix, self-hosted services, small VPSs, or home servers will understand the appeal quickly.

For them, Yakr offers:

> My messages stay easy to use, but the delivery infrastructure belongs to me and people I trust.

They may not need protection from a nation-state. They may simply dislike:

- global user directories;
- phone-number identity;
- central service dependency;
- opaque provider metadata collection;
- being locked into one company's client and infrastructure.

This group is also unusually willing to contribute relay capacity. The first healthy Yakr network is likely to grow from exactly this kind of community. See [homelab-relay.md](homelab-relay.md).

### Small trusted groups

The most natural **social model** for Yakr.

Examples:

- families;
- close friends;
- small businesses;
- technical teams;
- local community groups;
- expedition or overlanding groups;
- amateur radio and resilience communities.

These groups already have real-world trust relationships, so the social-relay concept feels natural rather than strange.

A family might run:

- a home relay;
- Dad's VPS;
- an adult child's home server;
- an old Android device as a lightweight mailbox.

Messaging continues as long as some part of that infrastructure remains reachable — quite different from asking strangers to participate in a public relay mesh.

### Journalists and small investigative teams

One of the strongest serious-use cases.

Example participants: journalist, editor, researcher, local source, trusted overseas relay operator.

The appeal is not perfect anonymity. It is **reducing dependence on one visible provider** and allowing infrastructure to be placed across jurisdictions.

Useful properties include:

- no phone-number account;
- invitation-based contact;
- self-selected relays;
- encrypted offline delivery;
- no central Yakr operator holding the social graph;
- replaceable infrastructure;
- optional high-privacy delivery modes.

**Caveat:** Yakr must not be marketed as sufficient source protection on its own. A source contacting a journalist from a home IP can still expose useful metadata to network observers or relay operators. Operational security, Tor, safe devices, and human procedure still matter. As a communications building block, Yakr can still be genuinely attractive.

### Activists and civil-society organisations

Especially small organisations operating where:

- mainstream platforms may be blocked;
- service providers may face legal pressure;
- local infrastructure may be unreliable;
- group members are spread across countries.

Key selling point:

> There is no single Yakr service to shut down.

If one relay disappears, contacts can publish replacements. That is a meaningful resilience property.

This audience will require very good UX. They cannot be expected to understand relay descriptors, TLS pins, mailbox epochs, or trust graphs. The app must feel like:

- Add trusted relay
- Relay unavailable → using backup relay

—not exposed protocol machinery.

### People in censored networks

Important later, though Yakr is **not** automatically censorship-resistant merely because it is decentralised. A fixed public Yakr relay can still be blocked.

Socially distributed relays have advantages:

- many independent domains and IPs;
- relays can appear and disappear;
- infrastructure can be personal rather than globally advertised;
- relay details are exchanged privately;
- no central discovery endpoint is required.

That may make blocking harder than blocking one large messaging service.

Future support for Tor, domain fronting (where legally and technically appropriate), pluggable transports, ordinary HTTPS camouflage, and relay rotation could strengthen this considerably.

### Disaster preparedness and resilience communities

A slightly different audience: primary concern is often **availability** rather than privacy.

Examples: emergency volunteers, remote communities, expeditions, off-grid groups, amateur radio operators, local resilience networks.

Future Meshtastic or LoRa transport ([ADR 010](adr/010-offline-mesh-transports.md)) fits particularly well:

```text
phone → local radio node → community relay → internet when available
```

Messages remain encrypted end-to-end while moving opportunistically across whatever transport exists. The Yakr message layer does not fundamentally care whether the blob travels over HTTPS, Tor, LAN, Meshtastic, LoRaWAN, satellite uplink, or a physical data mule. **The transport is replaceable** — and may eventually become one of Yakr's most distinctive properties.

### Businesses wanting private internal communication

A plausible audience, probably later.

A company could run its own relay infrastructure while avoiding a conventional central chat database. Potential buyers: law firms, consultancies, security firms, research organisations, private investment teams, small technology companies.

Attractive proposition:

> Employees communicate using company-controlled, replaceable relay infrastructure, while messages remain encrypted to recipient devices.

Businesses will expect device management, account recovery, employee revocation, compliance controls, backups, audit capability, reliable push notifications, and desktop clients. Some of those expectations conflict with privacy goals. **Enterprise Yakr** could become a separate product profile rather than the core protocol.

### Sovereignty-minded users

People interested in digital sovereignty — not necessarily security experts. They want:

- my data, my devices, my infrastructure;
- open protocols;
- ability to move providers.

They use Linux, open-source software, local AI, home automation, and self-hosted cloud services. Yakr fits that worldview:

> Your communications network is made from relationships and infrastructure you control, not an account granted by a platform.

That is an emotionally powerful message.

### Cryptocurrency and cypherpunk communities

Likely interested because Yakr shares several values: no central authority, cryptographic identity, open protocol, censorship resistance, self-operated infrastructure, minimised global identifiers.

**Caution:** do not position Yakr as a "crypto messenger." People may assume blockchain, tokens, wallet identities, or NFT integrations — none of which Yakr needs. The cypherpunk audience may appreciate it, but branding should stay firmly away from blockchain unless integrations are optional and peripheral.

---

## Who probably would not care

The average WhatsApp user is unlikely to switch because of architecture alone. Most people ask:

- Are my friends already there?
- Do messages arrive instantly?
- Can I restore my chats?
- Can I send photos?
- Does it work without thinking?

They do not normally care where the relay runs.

For Yakr to reach mainstream users, architecture must produce a **visible benefit**:

- communication survives provider shutdown;
- no phone number required;
- family-owned private network;
- better privacy;
- works through outages;
- user-controlled infrastructure.

Architecture is not itself a consumer feature.

---

## Primary initial audience

The strongest initial combination:

**Privacy-conscious technical users, families, small trusted groups, and independent organisations who want secure messaging without depending on a central platform.**

Accurate and achievable.

### Positioning lines (candidates)

| Line | Character |
|------|-----------|
| Private messaging powered by people you trust, not a platform you depend on. | Emotional |
| End-to-end encrypted messaging over infrastructure owned by your social graph. | Technically precise |

The first is stronger for adoption; the second is stronger for technical audiences.

---

## Adoption model

Most users do not need to operate relays. Perhaps only:

- one in five users, or
- one household, or
- one organisation member

needs to contribute reliable infrastructure. Everyone else joins through invitations and uses the relay graph already available to them.

That is much more realistic than requiring every person to self-host.

---

## The opportunity: a middle ground

| Model | Trade-off |
|-------|-----------|
| **Central messenger** | Easy, but controlled by one provider |
| **Pure peer-to-peer** | Independent, but unreliable on mobile |
| **Yakr** | Independent delivery through infrastructure owned by trusted people |

That middle ground is, in this view, the real opportunity.
