# Relay-Observer Privacy — What Each Party Learns

**Protocol:** `yakr-v1.0` + extensions  
**Status:** Normative (P1-4)  
**Related:** [security/analysis-v1.md](../security/analysis-v1.md) §8.5, [relay-capability-v1.md](./relay-capability-v1.md), [relay-authorization.md](./relay-authorization.md)

## Purpose

External review asked for an explicit answer to: **what can my friend's relay correlate?** This document is the normative privacy table. Implementers and operators MUST treat it as authoritative when describing relay metadata exposure.

## Wording standard (normative)

- **Correct:** *Relays do not receive plaintext message content or long-term identity keys inside ciphertext.*
- **Incorrect:** *Relays never know who sent or fetched* — IP addresses, timing, authorization artifacts, and operator context can deanonymise users even when ciphertext stays sealed.

## Deployment modes

| Mode | Description |
|------|-------------|
| **Single-hop mailbox** | Default reference path: `POST /v1/blobs` and `POST /v1/fetch` to the same paired operator relay |
| **Two-hop onion** | Optional: entry relay forwards wrapped blob to mailbox relay; entry sees poster IP, mailbox sees fetcher IP |
| **Capability auth** | `POST`/`fetch` authorized by relay-signed capability grant (preferred when relay advertises issuance key) |
| **Ticket auth (legacy)** | `RelayTicket` with stable `contact_id` and operator `issuer_signing_public` |

## Privacy table (normative)

Legend: **Yes** = observable in the honest-but-curious threat model; **No** = MUST NOT be derivable from protocol ciphertext; **Partial** = hidden from relay plaintext but linkable via metadata or side channels; **N/A** = not on this path.

| Observable | Mailbox relay (single-hop) | Entry relay (two-hop) | Network observer (TLS path) | Wake gateway (opt-in ADR 011) |
|------------|--------------------------|------------------------|-----------------------------|-------------------------------|
| **Poster IP on store** | Yes | Yes (first hop) | No (hidden inside TLS to entry) | N/A |
| **Fetcher IP on fetch** | Yes | Partial (mailbox relay; entry may not see fetch) | No | N/A |
| **TLS SNI / destination host** | Yes (operator's host) | Yes | Yes | Yes (platform push endpoint) |
| **Connection timing & volume** | Yes | Yes | Yes | Yes (wake timing) |
| **Mailbox tag** | Yes (`POST /v1/fetch` body or legacy GET path) | Partial (entry: tag inside onion; mailbox: yes) | No (encrypted to relay) | No |
| **Blob size / padding class** | Yes | Yes | Approximate (TLS record sizes) | No |
| **Inner message plaintext** | **No** | **No** | **No** | **No** |
| **Sender long-term identity key** | **No** (inside E2E) | **No** | **No** | **No** |
| **Recipient long-term identity key** | **No** | **No** | **No** | **No** |
| **Human-readable sender/recipient names** | **No** | **No** | **No** | **No** |
| **Stable `contact_id` (ticket auth)** | Yes when tickets required | Yes | No | No |
| **Operator `issuer_signing_public` (ticket auth)** | Yes (ticket field) | Yes | No | No |
| **`capability_id` (capability auth)** | Yes (grant + request binding) | Yes | No | No |
| **Cross-rotation `capability_id` link** | Partial (new salt → new id; operator may correlate by IP/timing) | Partial | Partial | No |
| **Presence / relay URL hints** | Yes (E2E inner `type=presence` still reveals poll timing after decrypt at client) | Yes | No | No |
| **Device push token** | No | No | No | Yes (if wake enabled) |

### Correlation notes

1. **Single-hop default:** the same operator relay that accepts a blob often serves the fetch. It can correlate poster IP, fetcher IP, tag, size, and time without breaking E2E.
2. **Two-hop:** splits poster vs mailbox observation but does not remove metadata — mailbox relay still learns tag and fetcher IP.
3. **Capabilities vs tickets:** capabilities remove stable global `contact_id` from wire auth but expose per-relay `capability_id`. Rotation with fresh `issuance_salt` unlinks ids across generations; operator context may still link sessions.
4. **Trust-graph polling:** recipients poll only relays learned from paired profiles/presence; a relay only sees fetches from users who already trust that operator.

## Relay authorization surface (by auth mode)

| Field on wire | Ticket auth (`require_tickets`) | Capability auth (`require_capabilities` or auto-detect) |
|---------------|----------------------------------|---------------------------------------------------------|
| `contact_id` | Sent | MUST NOT be sent |
| `issuer_signing_public` | Sent in ticket | MUST NOT be sent |
| `capability_id` | N/A | Sent (pseudonymous per relay + generation) |
| `capability_generation` | N/A | Sent |
| Relay-signed grant | N/A | Verified locally; grant id bound to requests |

## Operator guidance

| If you operate a relay for friends | You can learn |
|------------------------------------|---------------|
| Honest logging | IPs, tags, sizes, times, auth ids |
| You cannot learn (without breaking crypto) | Message plaintext, pairwise ratchet keys |
| Minimize exposure | Enable capability auth, disable ticket fallback when all clients support it, run TLS, rotate capabilities on compromise |

## References

- Threat model: [analysis-v1.md](../security/analysis-v1.md) §2–§3
- Capability rotation: [relay-capability-v1.md](./relay-capability-v1.md) §Rotation
- Fetch metadata: [fetch-algorithm.md](./fetch-algorithm.md)
