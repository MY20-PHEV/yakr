# Offline QR Pairing

**Protocol:** `yakr-v0.4` + `yakr-v1.0` extension  
**Status:** Implemented  
**Related:** [pairing-transcript-v1.md](./pairing-transcript-v1.md) (normative transcript; offline uses identical CBOR and hash as online rendezvous)

## Goal

Pair two contacts in person using three QR code scans and **no network** during the handshake.

## Flow

```text
① Inviter shows invite QR          yakr://invite/...
② Joiner shows pair-request QR     yakr://pair-request/...
③ Inviter shows pair-response QR   yakr://pair-response/...
```

Safety codes are verified by voice after step ①.

## URL Schemes

| URL prefix | Payload |
|------------|---------|
| `yakr://invite/` | Signed CBOR invite bundle |
| `yakr://pair-request/` | CBOR `PairingRequest` (joiner keys + profile) |
| `yakr://pair-response/` | CBOR `PairingResponse` (inviter ephemeral + profile) |

Offline invites set `rendezvous_hint` to `offline://qr`. Online `invite accept` rejects these.

## CLI

```bash
# Inviter (airplane mode OK)
yakr invite create --offline --no-wait --qr-out invite.png

# Joiner scans invite QR
yakr invite offline joiner-start yakr://invite/... --qr-out request.png

# Inviter scans request QR
yakr invite offline inviter-respond yakr://pair-request/... --qr-out response.png

# Joiner scans response QR
yakr invite offline joiner-finish yakr://pair-response/...
```

## Mobile API

```python
client.create_invite(offline=True)
client.start_offline_pairing(invite_url)      # → QrPayload for request
client.respond_offline_pairing(invite_url, request_url)  # → contact + response QR
client.finish_offline_pairing(response_url)   # → contact
```

## Delivery profiles

Each `PairingRequest` / `PairingResponse` embeds the sender's signed delivery profile.
Configure relay URLs in the profile **before** the meetup so messaging works once network returns.

## QR size limits

Large profiles may exceed a single QR (~3 KB). Use URL text transfer or multi-part QR in future if needed.

## Exit Criteria

- [x] Full pairing without HTTP rendezvous
- [x] Same master secret as online rendezvous path
- [x] Delivery profiles exchanged in pairing payloads
- [x] Pending joiner session persisted until finish
