# Platform Wake v1 (Optional)

**Status:** Draft (spec only; not yet implemented in reference clients)  
**Protocol:** `yakr-v1.2` extension  
**ADR:** [011 — Optional Platform Wake](../adr/011-optional-platform-wake.md)

## Summary

Platform wake is an **optional latency optimization** for mobile clients. Friend-operator relays store opaque blobs as today. When a recipient has opted in, a relay may ask an authorized **wake gateway** to send a silent platform notification (APNs on iOS, FCM on Android). The client then runs the normal [fetch algorithm](./fetch-algorithm.md).

**Normative:** Delivery MUST succeed without wake. Wake MUST NOT carry message plaintext or ciphertext.

## Actors

| Actor | Role |
|-------|------|
| **Mobile client** | Registers device token with relays; handles silent push → fetch |
| **Mailbox relay** | Stores blobs; forwards wake requests after `POST /v1/blobs` |
| **Wake gateway** | Holds APNs/FCM credentials; validates and rate-limits wake requests |

The wake gateway is typically operated by the app vendor. It is **not** a message store and MUST NOT receive blob ciphertext.

## User opt-in

Clients MUST treat platform wake as **opt-in**:

- Default: **off** (poll-only, ADR 008 baseline).
- When off: no device token registration; relays MUST NOT send wake requests for that client.
- UI SHOULD explain tradeoffs (see [Privacy](#privacy-disclosure)).

Implementations MAY expose:

```text
yakr wake enable [--gateway URL]
yakr wake disable
yakr wake status
```

## Registration (client → relay)

When wake is enabled, the client registers with **each mailbox relay** listed in its signed delivery profile that it polls for inbound mail.

### Endpoint (relay extension)

```http
PUT /v1/wake/registrations
Content-Type: application/json
```

### Request body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mailbox_tag` | base64url (32 bytes) | yes | Recipient mailbox tag this token listens on |
| `platform` | string | yes | `apns` or `fcm` |
| `device_token` | string | yes | Opaque platform token from OS |
| `environment` | string | apns only | `production` or `sandbox` |
| `gateway_url` | string | yes | HTTPS URL of wake gateway the relay should use |
| `expires_at` | int (ms) | yes | Registration expiry; relay MUST drop after |
| `wake_capability` | base64url | yes | Signed authorization (see below) |

### Wake capability (client-signed)

The client signs a short-lived capability so the wake gateway can verify the registration was intentional:

```text
wake_capability_message = CBOR({
  "protocol": "yakr-wake-v1",
  "identity_name": <string>,
  "mailbox_tag": <32 bytes>,
  "device_token": <string>,
  "gateway_url": <string>,
  "relay_url": <string>,      # this relay's canonical URL
  "expires_at": <ms>,
})
signature = Ed25519(signing_private_key, wake_capability_message)
wake_capability = base64url(signature || wake_capability_message)
```

Relays store registrations keyed by `(mailbox_tag, relay_url)` and MUST delete on expiry or explicit revoke.

### Revoke

```http
DELETE /v1/wake/registrations/{mailbox_tag_b64}
```

Client SHOULD revoke on logout, wake disable, or device token rotation.

### Re-registration

Clients SHOULD re-register when:

- Device token changes (APNs/FCM rotation)
- Delivery profile relay set changes (`profile publish` / `presence push`)
- `expires_at` approaches (recommended TTL: 7–30 days)

## Wake request (relay → gateway)

After a successful `POST /v1/blobs` (201), the relay MAY look up wake registrations for the blob's `mailbox_tag`. For each non-expired registration:

```http
POST {gateway_url}/v1/wake
Content-Type: application/json
```

### Request body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mailbox_tag` | base64url | yes | Tag that received mail |
| `device_token` | string | yes | From registration |
| `platform` | string | yes | `apns` or `fcm` |
| `environment` | string | apns only | `production` or `sandbox` |
| `relay_url` | string | yes | Requesting relay (for auth + rate limit) |
| `wake_capability` | base64url | yes | Copy from registration |
| `blob_received_at` | int (ms) | yes | When relay stored the blob |

Relays MUST NOT include `ciphertext`, sender hints, or inner message fields.

### Gateway behaviour

The wake gateway MUST:

1. Verify `wake_capability` signature and expiry.
2. Confirm `relay_url` matches the capability and is a known relay for this registration.
3. Rate-limit per `(relay_url, device_token)` (recommended: ≤ 60 wakes / hour / token, burst 10).
4. Send **silent** platform notification only.

The wake gateway MUST NOT log message content (there is none on this path).

### APNs payload (reference)

```json
{
  "aps": {
    "content-available": 1
  }
}
```

No `alert`, `sound`, or sender metadata. User-visible notifications are out of scope for v1.

### FCM payload (reference)

```json
{
  "data": { "wake": "1" },
  "priority": "high",
  "content_available": true
}
```

## Client behaviour after wake

On silent push / high-priority data message:

1. Run [fetch algorithm](./fetch-algorithm.md) against paired relays (same as poll worker).
2. Do not assume a specific sender or message count — fetch epoch lookback as usual.
3. If fetch finds nothing (race, duplicate wake, throttled push), exit quietly.

Poll worker intervals remain active as fallback (ADR 008).

## Privacy disclosure

Implementations SHOULD show users something like:

> **Optional faster delivery**  
> When enabled, relays you already use can ask our wake service to ping your phone when new mail arrives. Message content stays encrypted on relays; the wake service only sees a device handle and timing. Apple/Google process the notification per their policies. You can turn this off anytime; messages still arrive via normal fetch.

## Threat notes

| Risk | Mitigation |
|------|------------|
| Relay wake-spam without mail | Gateway rate limits; relay only wakes after blob store; user opt-out |
| Stolen device token | Token alone insufficient without gateway + capability validation |
| Compromised wake gateway | Cannot decrypt messages; can harass wake — revoke registration, disable opt-in |
| Global push outage | Poll-only fallback (normative) |

See [security analysis](../security/analysis-v1.md) §1.2 and wake metadata row.

## Relay configuration

Mailbox relays need only:

```text
WAKE_GATEWAY_ALLOWLIST=https://wake.example.yakr.app
```

Relays MUST reject registrations whose `gateway_url` is not on the allowlist (prevents token exfiltration to arbitrary URLs).

## Interop

| Component | v1.0 without wake | v1.2 with wake |
|-----------|-------------------|----------------|
| Blob POST/GET | Required | Unchanged |
| Wake registration | Ignored | Optional |
| Delivery correctness | Poll | Poll (wake optional) |

## Implementation status

| Piece | Status |
|-------|--------|
| ADR 011 | Accepted |
| This spec | Draft |
| `yakr-relay` wake endpoints | Not implemented |
| Wake gateway service | Not implemented |
| `yakr-mobile` APNs/FCM | Not implemented |
| CLI `yakr wake *` | Not implemented |

## References

- [ADR 011](../adr/011-optional-platform-wake.md)
- [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md)
- [fetch-algorithm.md](./fetch-algorithm.md)
- [yakr-protocol-v1.md](./yakr-protocol-v1.md) — delivery profiles, mailbox tags
