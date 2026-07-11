# Yakr Certified — Relay v1.0 checklist

Copy into your certification application. Mark each item **pass** / **fail** / **n/a** with evidence.

## HTTP API

- [ ] `GET /healthz` returns `{"status":"ok"}`
- [ ] `POST /v1/blobs` stores opaque ciphertext; returns 201
- [ ] `POST /v1/fetch` (preferred) or legacy `GET /v1/blobs/{tag}` returns stored blobs
- [ ] Binary fields use base64url without padding
- [ ] Relay does **not** delete blobs on fetch (TTL sweep only)

## Abuse limits

- [ ] Rejects `mailbox_tag` ≠ 32 bytes
- [ ] Rejects `expires_at` in the past
- [ ] Rejects ciphertext > 64 KiB
- [ ] Returns 429 when per-tag blob cap exceeded
- [ ] `test_phase9_relay_abuse.py` passes against this relay (or equivalent conformance)

## Security

- [ ] HTTPS with operator-controlled certificates (pins in client profiles)
- [ ] No decryption of application plaintext
- [ ] Minimal logging (no ciphertext or mailbox tag content in persistent logs)

## Rendezvous (if `role` includes rendezvous)

- [ ] `/v1/pair*` endpoints per [relay-rendezvous.md](../docs/spec/relay-rendezvous.md)
- [ ] Invite secret validation on pairing endpoints

## Capabilities (recommended homelab path)

- [ ] `--require-capabilities` or documented ticket bootstrap path
- [ ] Capability issuance key separate from messaging identity ([operator-identity-v1.md](../docs/spec/operator-identity-v1.md))

## Product metadata

- **Relay name / operator:**
- **Public URL:**
- **Deployment:** Docker / native / other
- **Data retention policy:**
