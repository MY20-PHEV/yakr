# ADR 011: Optional Platform Wake (Push)

**Status:** Accepted  
**Date:** 2026-07-10

## Context

Mobile clients receive mail by **outbound poll** to friend-operator relays (ADR 008). That path is correct on NAT, cellular, and iOS without inbound listeners. Polling alone works but can add minutes of latency when the app is backgrounded.

iOS (and similarly Android with FCM) supports **platform push** to wake a client so it can run a short background fetch. This is not transport-level P2P and does not require reverse tunnels or inbound TCP to the phone.

Earlier open decision **OD-03** defaulted the Phase 8 reference client to **polling only**. That was a scope choice for the first mobile scaffold, not a permanent ban on push.

Constraints for any push design in Yakr:

1. **Delivery correctness** MUST NOT depend on push (relay store + outbound fetch remain normative).
2. **Message plaintext** MUST NOT pass through the push path.
3. **Friend-operator relays** remain the blob store; decentralised message storage is unchanged.
4. **APNs / FCM send credentials** are per-app platform secrets — homelab relay operators MUST NOT each hold the Yakr app's global push key.

## Decision

Adopt an **optional platform wake** layer:

| Layer | Role | Required? |
|-------|------|-------------|
| Relay `POST /v1/blobs` | Store opaque ciphertext | **Yes** |
| Client `GET /v1/blobs` poll | Delivery correctness | **Yes** |
| Platform wake (APNs / FCM) | Latency / UX hint | **No** |

### 1. Normative delivery (unchanged)

Implementations MUST deliver and receive messages successfully with **no push infrastructure**. Poll intervals, app foreground, and background fetch tasks remain the baseline.

### 2. Optional opt-in wake

Clients MAY opt in to platform wake. Opt-in MUST be explicit (settings toggle or first-run choice). Users who do not opt in behave exactly as today.

When enabled:

1. Client registers a **platform device token** with each **trusted mailbox relay** it uses (see `docs/spec/platform-wake-v1.md`).
2. On successful `POST /v1/blobs`, the relay MAY request a wake from an **authorized wake gateway**.
3. Wake gateway holds APNs / FCM credentials and sends a **silent** platform notification.
4. Client wakes, runs the normal **fetch algorithm** (epoch lookback, decrypt, receipts) — no change to E2E crypto.

### 3. Central wake gateway (reference architecture)

The reference design uses **one wake gateway** operated by the Yakr app vendor (or self-hosted fork with its own app bundle):

```text
Sender ──POST blob──► Friend relay (Charlie)
                           │
                           └── wake request ──► Wake gateway ──► APNs/FCM ──► Recipient app
                                                                      │
Recipient ◄──────────── GET /v1/blobs (unchanged) ────────────────────┘
```

- Relays forward **wake requests only** — they do not hold APNs `.p8` keys.
- Wake gateway validates the relay is authorized to wake the registered token for that mailbox scope.
- No message body, ciphertext, or inner plaintext is sent to the wake gateway.

### 4. Privacy and trust tradeoffs (disclosed to users)

| What | Sees message content? | Sees metadata? |
|------|----------------------|----------------|
| Friend relay (today) | No | Mailbox tags, blob sizes, poll timing |
| Friend relay + wake | No | Above + device token handle, wake timing |
| Wake gateway | **No** | Device token, relay id, wake timing, rate |
| Apple / Google (platform) | **No** (silent wake) | Push delivery metadata per their policies |

Push improves latency, not security. Users SHOULD be told that wake registration delegates a **battery / notification wake capability** to relays they already trust for blob storage, and that a small amount of **activity timing** metadata reaches the wake gateway and platform provider.

### 5. Abuse and fallback

- Wake gateway MUST rate-limit per relay and per device token.
- Relays MUST only request wake after storing a blob (not on arbitrary schedule).
- Silent push is **best-effort** (Apple throttles; Android Doze). Poll remains mandatory fallback.
- Wake gateway outage or global APNs/FCM outage: **no delivery impact**, only slower UX.

### 6. Not in scope (v1 of this ADR)

- Reverse tunnels or persistent WebSocket from client to relay
- Message previews in notification UI (violates minimal-metadata goal)
- Per-operator APNs key distribution
- UnifiedPush (Android) — may be added later as an alternative wake transport

## Consequences

**Positive**

- Faster mobile UX on iOS without compromising relay-first correctness
- Blobs and E2E crypto path unchanged
- Homelab operators do not hold global app push secrets
- Clear opt-in with documented privacy tradeoffs

**Negative**

- Optional central wake gateway (platform plumbing, not message storage)
- Device token registration adds protocol surface and relay state
- Malicious or compromised relay can abuse wake (mitigated by gateway rate limits and user opt-out)
- iOS requires notification permission UX even for silent wake in many configurations

## Alternatives considered

| Alternative | Rejected because |
|-------------|------------------|
| Push-only delivery | Violates ADR 008; fails when push throttled or denied |
| Each relay holds APNs key | Global secret sprawl; one compromised homelab affects all users |
| Reverse tunnel to relay | Poor iOS background socket behaviour; unnecessary vs silent push |
| No push ever | Valid for privacy-max users; harms mobile UX for opt-in users |
| Message preview in push | Leaks metadata and UX content to Apple/Google lock screen |

## References

- `docs/spec/platform-wake-v1.md` — registration and wake request wire format
- ADR 007 — poll-on-relay remains baseline
- ADR 008 — NAT, mobile, outbound fetch correctness
- `docs/spec/fetch-algorithm.md` — fetch after wake
- `docs/security/analysis-v1.md` — wake metadata in threat model
