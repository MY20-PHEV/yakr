# ADR 010: Offline Mesh Transports (Meshtastic / LoRaWAN)

**Status:** Proposed (not implemented)  
**Date:** 2026-07-08

## Context

Yakr’s correctness path is **store-and-forward over reachable relays** (ADR 008): outbound POST from sender, outbound poll from recipient. Today those relays speak HTTPS on a VPS, homelab, or (future) ephemeral cloud deploy (ADR 009).

Some target users — journalists in censored regions, activist cells, rural/off-grid groups, disaster-preparedness communities — need messaging when **the public internet backbone is unavailable**, throttled, or too risky to use for metadata. That is not the same as “no link layer at all.” Low-power radio meshes (Meshtastic) and LoRaWAN gateways can provide **local or regional store-and-forward** with multi-hop routing, often without a central messaging platform.

Yakr already separates:

```text
Layer 2: E2E session crypto (unchanged)
Layer 3: Opaque blobs + mailbox tags + receipts (unchanged)
Layer 4: Relay mesh / ordered failover (new dial strings)
```

Nothing in the protocol requires HTTPS or TCP. **Meshtastic and LoRaWAN are candidate Layer 3–4 transport adapters**, not a redesign of pairing, profiles, or E2E encryption.

## Decision

### 1. Mesh transports are first-class future dial strings

Delivery profiles and presence MAY advertise mesh transports alongside `https` and `tor`:

```text
transport_hints / relay_descriptors[].transport:
  meshtastic
  lorawan
  https
  tor
```

Clients MUST preserve **ordered failover** (ADR 008): try the best available transport for current connectivity (e.g. Meshtastic when offline from internet; HTTPS when a gateway bridge is up).

### 2. Meshtastic — mesh node as mailbox hop

Meshtastic already provides store-and-forward, multi-hop routing, and optional MQTT/internet gateway bridging.

**Normative shape (conceptual):**

```text
Alice phone ──BLE/serial──► Meshtastic node A
                                │ RF mesh hops
                                ▼
                           Meshtastic node B (mailbox / gateway)
                                │
                           Bob phone (polls via BLE when in range)
```

- Yakr **opaque blobs** ride inside Meshtastic payloads (or a dedicated port/channel), fragmented to fit radio MTU.
- A **paired gateway node** MAY bridge mesh ↔ HTTPS `yakr-relay` when Starlink/MQTT returns — same operator in the trust graph, new `reachable` URL via presence.
- Meshtastic’s native channel crypto is **out of band** for Yakr; message confidentiality remains Yakr E2E.

**Trust:** The mesh **gateway operator** (or designated mailbox node) is a **paired relay operator** — same social-relay model as Charlie VPS. Peers learn node/gateway keys from signed profiles, not from a global directory.

### 3. LoRaWAN — gateway as paired operator relay

LoRaWAN is typically **device → gateway → network server → application**. For Yakr:

```text
Handset / edge device ──LoRa──► Gateway (paired operator)
                                      │
                                 yakr-relay or mesh bridge
```

- Best suited to **fixed sites** (homestead, newsroom backup, shelter) rather than pocket-to-pocket chat.
- Gateway operator appears in `relay_descriptors` like any HTTPS relay; LoRa is the **last-mile dial string** to reach that operator’s infrastructure when internet paths fail.

### 4. Pairing and pins on mesh

HTTPS uses TLS SPKI pins (`docs/spec/tls-endpoints.md`). Mesh transports use the **same idea on dial strings**:

| Transport | Trust anchor in signed profile |
|-----------|--------------------------------|
| `https` | `tls_spki_sha256` on relay descriptor |
| `tor` | Onion service id + pin (future) |
| `meshtastic` | Gateway/node public key or channel id + operator `name` |
| `lorawan` | Gateway operator identity + gateway id / region |

Pairing MAY occur **out of band when co-located** (QR over BLE/serial) — natural for mesh cells with no internet at bootstrap.

### 5. Fragmentation and size classes

Radio MTU is severely limited (often ~200–500 bytes practical per frame after headers).

Implementations MUST:

- Fragment Layer 3 blobs across multiple mesh frames with a stable reassembly id.
- Respect profile `blob_classes` — **text-first over mesh**; large attachments only when HTTPS (or another high-bandwidth transport) is available.
- Treat mesh delivery as **high-latency async** (minutes to hours) — aligned with Yakr’s offline mailbox model, not chat-over-TCP UX.

### 6. Grid-down reframing

**Without any link layer** (no internet and no radio path), async messaging cannot work. **With a paired Meshtastic/LoRaWAN path**, Yakr remains viable when the internet does not — the relay abstraction covers both global HTTPS mailboxes and local RF store-and-forward.

## Proposal (implementation sketch)

| Piece | Direction |
|-------|-----------|
| Profile / presence | `transport: ["meshtastic", "https"]`, mesh `reachable` dial strings |
| Adapter | `yakr_transport_meshtastic` — BLE/serial to node, protobuf/MQTT bridge optional |
| Adapter | `yakr_transport_lorawan` — ChirpStack / operator gateway integration |
| Relay image | Optional sidecar: mesh gateway ↔ `yakr-relay` on homelab |
| CLI | `yakr presence push --transport meshtastic` when gateway up |

Order of implementation (suggested): Meshtastic gateway bridge + HTTPS failover first; pure mesh-to-mesh without internet second; LoRaWAN gateway third.

## Open design questions

| Topic | Options |
|-------|---------|
| Meshtastic API | Native protobuf over serial vs MQTT module vs custom Yakr port |
| Mailbox on node | Full blob store on flash vs gateway forwards to paired HTTPS relay |
| Duty cycle / region | Ops documentation per jurisdiction; client rate limits |
| Metadata | Mesh gateways see timing and hop patterns — document in threat model |
| iOS | BLE to Meshtastic node when foreground; no background RF mailbox |

## Non-goals

- Replacing Meshtastic’s routing or inventing a competing RF stack
- Large attachments or voice over LoRa mesh as normative v1 mesh behavior
- Claiming nation-state anonymity — mesh gateways are curious intermediaries like VPS relays
- Wire-level phone-to-phone P2P without any store-and-forward node in path (still blob mailboxes)

## Consequences (if built)

**Positive**

- Credible story for off-grid / censorship / disaster scenarios without abandoning E2E or pairing-gated relays
- Reuses store-and-forward, profile failover, and social trust graph
- Complements ADR 009 (cloud relay when internet works) and Tor (future) when internet works but must be obfuscated

**Negative**

- Fragmentation, testing, and UX complexity
- Regulatory and hardware ops burden on users
- Very low bandwidth — feature matrix must be honest per transport

## References

- ADR 008 — NAT, mobile, relay-first delivery, ordered failover
- ADR 009 — ephemeral cloud relay when internet is available
- `docs/spec/tls-endpoints.md` — pin model generalizes to dial strings
- `whitepaper.md` §2.1, §17.3, §26.8
