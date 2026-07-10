# Yakr Presence and Group Relay Polling v1

**Status:** Draft (proposed `yakr-v1.1` extension)  
**Date:** 2026-07-07  
**Builds on:** `yakr-v1.0` (profiles, relay API, offline pairing)

## 1. Problem

`yakr-v1.0` delivery profiles are **signed, slow-moving configuration**: relay URLs, wrap secrets, and direct hints with a multi-day TTL. They answer:

> “How should you generally reach me?”

They do **not** answer:

> “Where am I reachable **right now**, and am I willing to act as a relay **right now**?”

The whitepaper assumes friends’ devices can be temporary relays. The v1 reference implementation separates clients from `yakr-relay` daemons and does not advertise live relay status to paired contacts.

This extension adds a **fast, ephemeral presence layer** on top of existing pairwise sessions, while keeping **group relays** as the reliable store-and-forward poll point.

## 2. Design goals

1. **Paired peers exchange live reachability** — URLs, relay role, expiry.
2. **Any client may act as a relay** when policy allows **and** it publishes dialable `reachable` URLs (see §6).
3. **A contact group shares at least one reachable relay** for offline delivery and fetch polling (typically a friend’s VPS/homelab — not a NAT’d phone on cellular).
4. **Senders adapt routes** using fresh presence first, signed profile second.
5. **No global presence directory** — updates flow only over existing pairwise encrypted channels (or via blobs on group relays).

### Mobile-first constraint

Typical users are on phones behind NAT/CGNAT. **Receiving mail does not require inbound connectivity** — recipients poll shared relays outbound. **Acting as a mailbox for remote peers requires a dialable address**; embedded relay on cellular without IPv6 or hole punch is not a delivery strategy. See [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md).

## 3. Non-goals (v1.1)

- Mandatory NAT hole punching (optional future optimization; relay failover remains correctness path)
- Public relay discovery or DHT
- Replacing signed delivery profiles
- Guaranteed delivery latency bounds
- Phones as internet-reachable mailboxes on cellular without dialable `reachable` URLs

## 4. Architecture overview

Two routing layers:

```text
┌─────────────────────────────────────────────────────────────┐
│ Layer A — Presence (ephemeral, minutes)                      │
│   "I'm at X, relay ON until 15:30, mailbox role"             │
│   Encrypted inner message type=presence to each contact       │
└─────────────────────────────────────────────────────────────┘
                              ↓ if stale / missing
┌─────────────────────────────────────────────────────────────┐
│ Layer B — Delivery profile (signed, days)                    │
│   relay_descriptors, wrap_secrets, direct_hints, epochs      │
│   From pairing, profile push, or GET /v1/profile             │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer C — Group relay (poll)                                 │
│   Shared friend relay stores opaque blobs; all peers poll    │
│   GET /v1/blobs/{mailbox_tag} on a schedule                  │
└─────────────────────────────────────────────────────────────┘
```

### Contact group model

A **contact group** is not a new global object. It emerges from overlapping delivery profiles:

```text
Alice's profile lists: Dennis relay, Charlie relay
Bob's profile lists:   Dennis relay, Eve relay
Carol's profile lists: Dennis relay

→ Dennis is the shared reachable relay for this friend group
```

**Requirement for mobile-only groups:** at least one member (or their home VPS) runs a **group relay** — an HTTP endpoint all peers can reach for store-and-forward. Others poll it outbound. A phone MAY **embed** relay APIs only when presence includes a **dialable** `reachable` URL (same LAN, IPv6, or post-punch) — not merely because relay software is running behind NAT.

Messaging does **not** require every peer to be online simultaneously. It requires:

1. Someone reachable to **store** blobs (group relay)
2. Recipients to **poll** that relay when they come online

## 5. Presence message

### 5.1 Inner message type

Extend inner message types:

```text
text | receipt | profile | presence
```

`presence` body is JSON (UTF-8), encrypted under the pairwise session like any other message.

### 5.2 Presence payload

```json
{
  "version": 1,
  "device_id": "abc123",
  "issued_at": 1700000000000,
  "valid_until": 1700001800000,
  "reachable": [
    {
      "url": "http://192.168.1.12:18100",
      "transport": "http",
      "roles": ["direct", "mailbox"]
    }
  ],
  "relay": {
    "active": true,
    "roles": ["mailbox"],
    "accepts_for": "contacts",
    "max_blob_bytes": 65536,
    "wifi_only": true,
    "charging_only": false
  },
  "group_relays": [
    {
      "name": "dennis",
      "url": "https://relay.dennis.example:8080",
      "role": "both"
    }
  ],
  "capabilities": ["embedded_relay", "direct_ingest"]
}
```

| Field | Meaning |
|-------|---------|
| `valid_until` | Peers MUST discard presence after this time (ms) |
| `reachable[]` | Endpoints remote peers can dial **right now** (required if `relay.active`) |
| `relay.active` | Device is running embedded relay HTTP API **and** accepts inbound on `reachable[]` |
| `relay.roles` | `entry`, `mailbox`, or `both` |
| `group_relays[]` | Hints for shared poll points (may mirror profile) |
| `capabilities` | Optional feature flags |

**TTL:** default 15 minutes; max 60 minutes. Clients SHOULD refresh presence before expiry when network is available.

### 5.3 Trust rules

1. Only accept `presence` from a **paired contact** (verified session).
2. `device_id` MUST match a known device for that contact (or be stored on first sight with user prompt in UI implementations).
3. `reachable` URLs MUST NOT override `wrap_secret` requirements from the signed profile for onion routes — presence may add **direct** or **embedded relay** endpoints only when accompanied by valid session context.
4. Presence is **advisory** for routing; signed profile remains authoritative for cryptographic relay parameters.

## 6. Embedded client relay

Embedded relay is **opportunistic**, not the mobile delivery path. Remote peers can only POST blobs to your device if they can reach a URL in `reachable[]`. Behind NAT on cellular, that is usually impossible without IPv6 or hole punching — so `relay.active` MUST be `false`.

When `relay.active: true`, the client MUST:

1. Expose the same HTTP surface as `yakr-relay` (subset below).
2. Include at least one dialable URL in `reachable[]` with matching `roles`.
3. Set `relay.active: false` when policy blocks relaying **or** when no dialable URL exists.

**Invalid state (MUST NOT advertise to contacts):** `relay.active: true` with empty `reachable[]`, or `reachable` URLs that are loopback-only / unroutable from the sender’s network.

| Endpoint | Required when |
|----------|----------------|
| `GET /healthz` | always |
| `POST /v1/blobs` | `mailbox` or `both` role |
| `GET /v1/blobs/{tag}` | `mailbox` or `both` role |
| `POST /v1/relay` | `entry` or `both` role |
| `POST /v1/ingest` | `mailbox` or `both` role |
| `POST /v1/pair` | rendezvous (see §7.4) |
| `POST /v1/pair/register` | rendezvous — inviter wait session |
| `GET /v1/pair/{invite_tag}` | rendezvous — poll for pairing response |

Implementations MAY enforce the same abuse limits as reference `BlobStore` (64 KiB, per-tag cap).

### Policy gates (recommended)

Align with mobile `DeviceSettings`:

- `relay_enabled` user preference
- Wi‑Fi only / charging only (permission to run a listener — **not** proof of internet reachability)
- Battery threshold
- Foreground service or OS background execution rules

When policy blocks relaying, or when no dialable `reachable` URL is available, client MUST send `relay.active: false` in the next presence update.

## 7. Group relay polling

### 7.1 Send path

When Alice sends to Bob:

```text
1. Load Bob's freshest presence (< valid_until)
2. If Bob.relay.active and Bob.reachable has a dialable URL → try embedded relay / direct
3. Else use Bob's signed delivery profile relay_descriptors
4. Else use shared group_relays from presence or profile
5. Encrypt → outer blob → POST to chosen mailbox relay
```

### 7.2 Fetch path (poll)

When Bob fetches from Alice (or polls all contacts):

```text
1. For each contact, derive mailbox tags (epoch + lookback + decoys)
2. For each tag, GET /v1/blobs/{tag} from:
     a. contact presence reachable URLs (if relay.active)
     b. contact profile mailbox descriptors
     c. shared group relay URLs
3. Decrypt, update presence cache if profile/presence inner messages arrive
```

Polling interval is implementation-defined (mobile: 30s charging / 5–15 min on battery). **No push requirement** in v1.1 — relay poll is the baseline.

### 7.3 Why group relay is enough for offline

```text
Alice sends while Bob is offline
  → blob stored on Dennis's group relay (opaque tag)

Bob comes online later
  → FetchWorker polls Dennis's relay
  → decrypts message
```

Peers do not need inbound connectivity for **receive**. They need a **shared outbound-reachable** store.

### 7.4 Group relay as pairing rendezvous

The invite `rendezvous_hint` MAY point at a **group relay** — the same URL used for message store/fetch. Pairing then reuses reachable group infrastructure instead of a separate rendezvous server on the inviter's phone.

| Mode | `rendezvous_hint` | When |
|------|-------------------|------|
| **Offline QR** | `offline://qr` | In person, no network |
| **Relay rendezvous** | `https://relay.dennis.example` | Remote pairing via group relay |
| **Local rendezvous** | `http://192.168.x.x:8090` | Inviter device on LAN (current CLI) |

#### Flow (relay rendezvous)

The relay is a **pairing mailbox** — it stores opaque pairing payloads; crypto stays on clients.

```text
① Alice: invite with rendezvous_hint = Dennis relay URL (in QR)
② Alice (online): POST /v1/pair/register — wait for joiner
③ Bob: scans QR → POST /v1/pair { request } to Dennis relay
④ Dennis relay: stores request OR forwards to Alice's open wait session
⑤ Alice client: inviter_complete_pairing locally
        → POST /v1/pair/response { response } to relay
⑥ Bob: GET /v1/pair/{invite_tag} — polls until response arrives
⑦ Both derive master_secret; delivery profiles exchanged in pairing payloads
```

`invite_tag` = opaque tag derived from `invite_secret` (like mailbox tags).

#### Mobile-friendly

Neither phone needs inbound HTTP. Both **poll outbound** to Dennis:

- Inviter polls for joiner's `PairingRequest`
- Joiner polls for inviter's `PairingResponse`

Same pattern as message fetch.

#### One URL, two roles

```text
https://relay.dennis.example
  /v1/pair*       bootstrap new contacts (rendezvous)
  /v1/blobs/*     store/fetch messages (mailbox)
```

After pairing, a group relay SHOULD appear in **`relay_descriptors` only for peers paired with that relay operator**. Joiners MAY use the rendezvous relay for pairing and poll it for inbound mail without advertising it in their own profile.

#### Security

- Relay sees pairing volume/timing, not plaintext (opaque CBOR).
- `invite_secret` binding and one-time consume (`409` on replay) as in reference rendezvous.
- Rate-limit `/v1/pair*` alongside blob abuse limits.

## 8. Presence distribution

Peers SHOULD push presence updates:

| Trigger | Action |
|---------|--------|
| Network up / down | Push new presence |
| Wi‑Fi ↔ cellular | Push |
| `relay_active` changes | Push immediately |
| Periodic timer | Refresh before TTL (e.g. every 10 min) |
| After successful direct session | Push (whitepaper §9.3) |

Transport options (any pairwise channel):

1. **Encrypted message** to each contact (`type=presence`) — preferred
2. **Store on group relay** as encrypted blob (receiver sees it on poll)
3. **Direct HTTP** `POST /v1/presence` (optional future endpoint on embedded relay)

v1.1 normative minimum: **(1) encrypted inner message** to each paired contact.

## 9. Routing precedence (normative)

For delivery to contact `C`:

```text
priority 1: fresh presence.reachable with matching role
priority 2: fresh presence.group_relays (mailbox)
priority 3: signed profile.direct_hints (2s timeout)
priority 4: signed profile.relay_descriptors
priority 5: stale presence / stale profile (warn, retry)
```

Senders MUST NOT use expired presence (`valid_until < now`).

## 10. Relationship to delivery profiles

| Concern | Profile (signed, slow) | Presence (ephemeral, fast) |
|---------|------------------------|----------------------------|
| Wrap secrets for onion | ✓ | ✗ |
| Long-term relay identity | ✓ | hint only |
| Current URL / IP | optional hints | ✓ primary |
| Relay on/off right now | ✗ | ✓ |
| Group relay URLs | ✓ | ✓ cached copy |
| TTL | days | minutes |

Profile changes (new VPS, new wrap secret) still require `profile push`. Presence cannot introduce new wrap secrets without a profile update.

## 11. Example: five friends on mobile

**Setup (once):**

- Invite QR uses `rendezvous_hint: https://relay.dennis.example` OR offline QR in person
- Remote add: Bob posts pair-request to Dennis relay; both poll for completion
- Everyone's profile lists Dennis as group relay

**Runtime:**

```text
Charlie (home Wi‑Fi, charging):
  presence: relay.active=true, reachable=http://192.168.0.5:18100
  → can store blobs for friends on same LAN

Alice (LTE, behind CGNAT):
  presence: relay.active=false, reachable=[]
  → sends via outbound POST to Dennis/Charlie relays in profiles

Bob (offline):
  → no presence; peers use profile + Dennis relay

Bob (later, LTE):
  → polls Dennis's relay outbound every 5 min
  → receives all pending blobs
```

No peer needs a static public IP for **receive**. Dennis (or any always-on, internet-reachable node) is the **poll anchor**. Charlie on home Wi‑Fi may contribute **same-LAN** mailbox capacity when `reachable` lists a local address; that does not make Charlie a relay for remote cellular peers unless IPv6 or hole punch provides a dialable URL.

## 12. Error codes (proposed)

```text
YAKR_ERR_PRESENCE_STALE
YAKR_ERR_RELAY_UNAVAILABLE
YAKR_ERR_NO_GROUP_RELAY
```

## 13. Implementation phases (reference)

| Step | Deliverable |
|------|-------------|
| 10a | `type=presence` message + CLI push/poll |
| 10b | Embedded relay (policy-gated; dialable `reachable` required) |
| 10c | Sender routing: presence → profile → group relay |
| 10d | FetchWorker polls group relays from presence cache |
| 10e | Testkit: five-client sim with one VPS relay |

## 14. Security considerations

- **Presence spoofing:** mitigated by E2E encryption to pairwise session only
- **Relay flooding:** embedded relays use same abuse limits; group relay uses tickets optional
- **Stale routes:** short TTL limits window of bad hints
- **Metadata:** presence updates are encrypted; group relay still sees poll timing and tags

See `docs/security/analysis-v1.md` — to be extended with presence threat notes in Phase 10.

## 15. References

- `docs/spec/yakr-protocol-v1.md` — baseline wire formats
- `docs/spec/phase-5-profiles.md` — delivery profiles
- `docs/spec/offline-pairing.md` — in-person bootstrap
- `docs/adr/008-nat-reachability-and-mobile-delivery.md` — mobile NAT, relay-first delivery
- `whitepaper.md` §3.3, §6.4, §9.3
