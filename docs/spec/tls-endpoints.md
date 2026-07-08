# TLS endpoint authentication

**Protocol:** `yakr-v0.5` profile extension  
**Status:** Implemented (reference client + mesh tests)  
**Applies to:** Every peer HTTPS endpoint (direct P2P and relay mailboxes)

## Requirement

Every Yakr peer endpoint **MUST** speak **HTTPS**. Trust is **not** from public CAs. Clients verify the server certificate by **SPKI SHA-256 pin** carried in the paired contact's **signed delivery profile**.

Future transports (Tor, etc.) use the same pin model on top of their dial string.

## Profile field

`endpoint_tls_spki_sha256` — 32 raw bytes, SHA-256 of the DER `SubjectPublicKeyInfo` of the peer's TLS public key for **direct** endpoints (`direct_hints`).

Included in the signed CBOR payload of `DeliveryProfile` (protocol `yakr-v0.5`).

## Relay descriptor field

Each `relay_descriptors[]` entry MAY include `tls_spki_sha256` — the **relay operator's** TLS pin (same format as above).

When Alice advertises Charlie's relay in her signed profile, she copies Charlie's `wrap_secret` **and** `tls_spki_sha256`. Peers who only know Alice (not Charlie) learn Charlie's TLS pin from Alice's profile — no direct pairing with every relay operator required.

Pins on relay descriptors are populated automatically when publishing via `authorized_publish_relays` (from paired operator profiles).

## Identity material

Each `Identity` holds an ECDSA P-256 key pair used only for TLS. The SPKI pin is published in profiles; the private key never leaves the device.

Certificates are self-signed, short-lived (renewable), and named `CN=yakr-{identity.name}`.

## Verification

On every HTTP request to a paired peer or authorized relay:

1. Require `https://` URL (plain HTTP rejected when `YAKR_REQUIRE_TLS=1`)
2. Complete TLS handshake
3. Hash peer certificate SPKI; MUST equal pin from signed profile for that operator
4. Proceed with Yakr protocol (blobs, pairing, profile fetch, etc.)

Message confidentiality remains end-to-end encrypted; TLS prevents transport MITM and hides ciphertext from the network path.

## Bootstrap (pairing rendezvous)

Before a joiner has the relay operator's delivery profile, the **invite** may include optional `rendezvous_tls_spki_sha256` (signed by inviter). Joiners pin the rendezvous relay to this value during `POST /v1/pair`.

After pairing, the relay operator's profile pin is authoritative.

## Invite field

```text
rendezvous_tls_spki_sha256: optional 32 bytes in signed invite CBOR
```

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `YAKR_REQUIRE_TLS` | `1` | Reject plain `http://` URLs |
| `YAKR_TLS_INSECURE` | `0` | Skip pin verification (dev only) |

## Relay health

`GET /healthz` returns `name`, `role`, `status` over HTTPS like all other endpoints.

## See also

- [presence-minimal.md](./presence-minimal.md) — ephemeral `reachable_url` (HTTPS or future `tor:`)
- [relay-failover.md](./relay-failover.md) — pin per operator in failover list
