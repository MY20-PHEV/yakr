# Relay Rendezvous Pairing

**Status:** Implemented (reference client + `yakr-relay`)  
**Protocol:** `yakr-v0.4` invite + pairing payloads on `yakr-v1.0` relay API

## Summary

A group relay MAY serve as the **pairing rendezvous** — the same HTTP host used for `/v1/blobs` store/fetch. Neither phone needs inbound connectivity; both poll outbound.

| Mode | `rendezvous_hint` | When |
|------|-------------------|------|
| Offline QR | `offline://qr` | In person, no network |
| **Relay rendezvous** | `https://relay.example:8090` | Remote pairing via group relay |
| Local rendezvous | `http://192.168.x.x:8090` | Inviter serves HTTP on LAN |

## Relay API (pairing mailbox)

| Endpoint | Role |
|----------|------|
| `POST /v1/pair/register` | Inviter registers wait session (`invite_secret`) |
| `GET /v1/pair/pending/{invite_tag}` | Inviter polls for joiner's `PairingRequest` |
| `POST /v1/pair` | Joiner posts opaque pairing request CBOR |
| `POST /v1/pair/response` | Inviter posts opaque pairing response CBOR |
| `GET /v1/pair/{invite_tag}` | Joiner polls for response |

`invite_tag` = base64url(SHA256(`invite_secret`)).

The relay stores opaque CBOR only — no private keys, no plaintext.

## CLI flow

```bash
# Alice (paired with relay operator Charlie beforehand)
yakr invite create --rendezvous https://relay.example:8090 --no-wait
yakr invite relay wait

# Bob (does not need to be paired with Charlie)
yakr invite accept "yakr://invite/..." --name alice
```

## Security

- Relay sees pairing volume and timing, not content.
- `invite_secret` binding; one-time consume (`409` on replay).
- Rate-limit `/v1/pair*` alongside blob abuse limits.

## Demos

| Script | Layout |
|--------|--------|
| `./scripts/demo_relay_group_pairing.sh` | All-local (Charlie on `:19080`) |
| `./scripts/demo_vps_charlie_relay.sh` | Alice + Bob in Docker, Charlie on VPS |
| `VPS_HOST=user@host ./scripts/deploy_charlie_vps.sh` | Deploy relay to remote host |

See [demo-vps-charlie.md](../demo-vps-charlie.md).

## Exit criteria

- [x] Pairing mailbox on `yakr-relay` (SQLite `PairingStore`)
- [x] CLI `invite create --rendezvous`, `invite relay wait`, `invite accept` via relay
- [x] Bidirectional messaging after relay rendezvous pairing
- [x] Testkit `test_relay_rendezvous.py`
