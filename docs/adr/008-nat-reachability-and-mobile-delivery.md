# ADR 008: NAT, Reachability, and Mobile Delivery

**Status:** Accepted  
**Date:** 2026-07-08

## Context

Typical Yakr users are on **mobile phones**, switching between cellular and home/work Wi‑Fi. Almost all of these networks place the device behind NAT (often carrier-grade NAT on LTE/5G). Inbound connections to the phone are not generally possible without hole punching, global IPv6, or same-LAN addressing.

Yakr’s store-and-forward model already works without inbound reachability:

- **Send:** outbound `POST /v1/blobs` to a **reachable** relay in the friend graph
- **Receive:** outbound `GET /v1/blobs/{tag}` poll on the same relays

Earlier drafts implied that phones could **embed a relay** when on Wi‑Fi + charging, acting as a mailbox for remote peers. That is only useful when the device publishes a **dialable** `reachable` URL. Running relay software behind NAT without a reachable address does not help remote peers — they cannot POST blobs to you.

## Decision

### 1. Relay-first correctness (normative)

Mobile and NAT’d clients MUST NOT depend on inbound connectivity for message delivery. The correctness path is:

1. **Friend-operator relays** (VPS, homelab) listed in signed `relay_descriptors`
2. **Outbound POST** from sender to recipient mailbox tags on those relays
3. **Outbound poll** from recipient when online

This works on cellular, home Wi‑Fi, and CGNAT without hole punching.

### 2. Embedded relay is opportunistic only

A client MAY embed the relay HTTP API and set `relay.active: true` in presence **only when** `reachable[]` contains at least one URL that remote peers can dial **right now**, for example:

| Case | Example `reachable` |
|------|---------------------|
| Same LAN | `http://192.168.x.x:port` |
| Global IPv6 | `https://[2001:db8::1]:port` |
| Post-punch session | ephemeral endpoint (future) |

**Invalid:** `relay.active: true` with empty `reachable[]`, or URLs that only work from localhost. Implementations MUST NOT advertise embedded relay to contacts unless dialability is verified (e.g. same-network, IPv6, or successful punch).

On **cellular without IPv6/punch**, `relay.active` MUST be `false`. Wi‑Fi + charging policy gates **whether** the app may run a listener; it does not imply internet reachability.

### 3. `direct_hints` semantics

Signed `direct_hints` are **best-effort** endpoints (2s timeout on send). They are not a substitute for relays on NAT’d mobile. Valid uses:

- Same LAN fast path
- Known public / IPv6 endpoint
- Post-punch direct ingest (future)

Send order remains: direct hints → profile relays → sender relays (see `relay-failover.md`).

### 4. Hole punching (deferred, optional)

UDP hole punching MAY be added later as a **latency optimization** when both peers are online simultaneously. It is not required for delivery and MUST fall back to relay failover on failure. Mobile↔mobile behind symmetric CGNAT remains relay-only in the common case.

### 5. Presence vs profile

| Layer | Answers |
|-------|---------|
| **Signed profile** | Who operates which relays; wrap secrets; TLS pins (slow, authoritative) |
| **Presence** | Where am I right now; is my embedded listener dialable (fast, advisory) |

Recipients do not need inbound connectivity to **receive** — only outbound poll to shared relays.

## iOS and cellular constraints

This section records platform and carrier facts that bound what “direct” and “embedded relay” can mean for a typical UK mobile user (iPhone on LTE/5G, sometimes home Wi‑Fi).

### Cellular IPv6 (UK and similar)

Many UK carriers assign IPv6 on mobile data (e.g. EE on current plans; Three in many configurations; others vary). **Having an IPv6 address is not the same as being an internet-reachable server.**

| Factor | Effect on Yakr |
|--------|----------------|
| Carrier inbound firewall | Some operators block unsolicited inbound on mobile data even when the handset has global IPv6 — P2P cannot rely on “v6 fixes NAT.” |
| 464XLAT / CLAT | IPv4 traffic is translated; the v6 assignment is not “home broadband dual-stack” semantics. |
| Privacy / rotating addresses | IPv6 on handsets may change; `reachable` must be fresh via presence, not a static profile hint. |
| Outbound-only default | Phones are designed as clients; carriers expect outbound connections, not public listeners. |

**Normative:** implementations MAY attempt direct delivery to a contact’s IPv6 `reachable` URL when presence is fresh and dialability is verified. They MUST NOT treat “cellular has IPv6” as sufficient for `relay.active: true` or as a replacement for friend-operator relays.

### iOS listener and background execution

Apple does not forbid binding a listening socket while the app is **foreground**, but iOS does not support a phone acting as a **persistent mailbox** for async messaging:

1. **Background suspension** — shortly after leaving the foreground, the app is suspended. [TN2277](https://developer.apple.com/library/archive/technotes/tn2277/_index.html) requires **closing listening sockets in background** and reopening in foreground; otherwise peers connect to a deaf socket.
2. **No general inbound wake** — there is no supported API to resume the app because a remote peer opened a TCP/UDP connection to the device (unlike push or outbound background URLSession).
3. **Async delivery model** — Yakr recipients are usually offline or backgrounded when messages arrive; an iPhone cannot reliably accept `POST /v1/blobs` from the internet in that state.

**Normative:** iOS (and similarly constrained Android background policies) MUST use **outbound poll** to friend-operator relays as the receive path. Embedded relay on iPhone is limited to **foreground + dialable `reachable`** (typically same LAN) or future explicit user opt-in foreground service — not background cellular mailbox duty.

**Optional:** Clients MAY use **platform wake** (silent APNs / FCM) as a latency hint to run the same outbound fetch sooner. Wake is opt-in, carries no message plaintext, and is not required for correctness. See [ADR 011](011-optional-platform-wake.md).

### Practical matrix (iPhone-first)

| Scenario | Direct / embedded relay | Correctness path |
|----------|-------------------------|------------------|
| App backgrounded, cellular | No inbound listener | Poll relays |
| App backgrounded, home Wi‑Fi | No inbound listener | Poll relays |
| App foreground, same LAN as peer | LAN `reachable` / `direct_hints` may work | Relay if direct fails |
| App foreground, cellular IPv6 | Rare; carrier may block inbound | Relay |
| Either peer offline (async) | N/A | Store on relay; poll later |

This is why Yakr is **decentralized E2E messaging with social relays**, not transport-level P2P between phones across the public internet.

## Consequences

**Positive**

- Clear product story for mobile: messages work via friend-graph relays
- No false expectation that phones become public servers on cellular
- Embedded relay scoped to LAN/IPv6/punch niches

**Negative**

- Groups without at least one reachable relay operator (VPS/homelab) cannot complete remote pairing or store-and-forward across the internet
- Direct latency benefits are limited to same-LAN, rare foreground+reachable cases, or future punch — not default iPhone cellular use

## References

- `docs/spec/presence-v1.md` — presence and embedded relay rules
- `docs/spec/relay-failover.md` — send ordering
- `docs/spec/presence-minimal.md` — implemented presence subset
- ADR 007 — presence layer and group relays
- ADR 010 — offline mesh transports when internet backbone is unavailable
- ADR 011 — optional platform wake (push as fetch hint, not delivery path)
