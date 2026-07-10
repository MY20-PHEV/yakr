# TLS Pin Lifecycle — Rotation and Recovery

**Protocol:** `yakr-v1.0` extension  
**Status:** Draft (P0-9)  
**Related:** [tls-endpoints.md](./tls-endpoints.md), [profile-replay-policy.md](./profile-replay-policy.md), [delivery_profile.md](./delivery_profile.md)  
**Review:** [github-follow-up-critique-2026-07-10.md](../reviews/github-follow-up-critique-2026-07-10.md)

## Purpose

Yakr endpoints authenticate with **SPKI SHA-256 pins** in signed delivery profiles, not public CAs. This document specifies operational lifecycle: renewal, compromise, overlap, and recovery — part of the protocol trust model, not an implementation detail.

## Pin sources

| Pin location | Describes |
|--------------|-----------|
| `DeliveryProfile.endpoint_tls_spki_sha256` | Peer direct HTTPS endpoint |
| `RelayDescriptor.tls_spki_sha256` | Relay operator HTTPS endpoint |
| `InviteBundle.rendezvous_tls_spki_sha256` | Bootstrap rendezvous only (pre-profile) |

Authoritative pins after pairing come from **signed delivery profiles** and [profile-replay-policy.md](./profile-replay-policy.md).

## Scenarios (normative targets)

### 1. Planned certificate renewal

**Trigger:** Operator rotates TLS cert (expiry, key hygiene).

**Required behaviour:**

1. Operator generates new TLS key; computes new SPKI pin.
2. Operator publishes delivery profile with **incremented `version`** and new pin(s).
3. Peers accept update per profile replay policy (`incoming.version > stored`).
4. **Overlap window:** operator MAY serve **both** old and new cert on the same endpoint during window (default recommendation: 24–72h) so in-flight clients using old pin still connect.
5. After overlap, old cert removed; peers with only old pin fail TLS until they fetch new profile.

**Client rule:** On TLS pin mismatch, attempt profile refresh from last-known-good relay fetch before failing permanently.

### 2. Relay host compromise

**Trigger:** Operator believes relay TLS key or host is compromised.

**Required behaviour:**

1. Operator revokes compromised cert; deploy new cert + pin.
2. Operator bumps profile `version` with new `relay_descriptors` pins.
3. Operator SHOULD treat `wrap_secret` as compromised — rotate wrap secret and update descriptors.
4. Peers reject old profile versions (replay policy blocks rollback).

**Open:** explicit `revoked_pins[]` or `relay_generation` field in profile — not in v1.0.

### 3. Operator loses TLS key (no compromise)

**Trigger:** Key loss without attacker access.

**Recovery without full re-pairing:**

- If operator still holds **signing identity**: publish new profile with new TLS key and bumped version.
- Peers update pins on next successful profile fetch.

**If signing identity also lost:** contacts cannot authenticate new pins — **full re-pairing required** (new invite).

### 4. Replay of old signed profile

**Mitigation (implemented):** [profile-replay-policy.md](./profile-replay-policy.md) rejects `incoming.version < stored`.

**Residual risk:** if attacker captured **newer** profile at compromise time and replays it after operator recovery, peers may restore bad pins. Mitigation: operator bumps version again with `valid_from` after recovery; consider short `valid_until` on profiles (default 7d).

### 5. Overlapping relay keys during rotation

| Phase | Relay serves | Clients accept |
|-------|--------------|----------------|
| Overlap | old + new cert (SNI or dual-listener) | either pin from active profile version |
| Cutover | new cert only | new pin only |

Normative default overlap: **48 hours** (operator-configurable; document in homelab runbook).

## Client verification summary

```text
TLS connect → hash SPKI → compare to pin from:
  1. contact.delivery_profile for that operator (relay or direct)
  2. else invite.rendezvous_tls_spki_sha256 (pairing only)
→ mismatch: try profile refresh → retry once → fail closed
```

## Relay operator checklist

- [ ] Publish profile **before** switching TLS cert when possible
- [ ] Keep overlap window for old cert
- [ ] Rotate `wrap_secret` on compromise
- [ ] Bump profile `version` on every pin change
- [ ] Document recovery path for contacts (group message / out-of-band)

## Open work (P0-9)

| Item | Status |
|------|--------|
| Normative overlap duration | Draft default 48h |
| Profile refresh on TLS failure | Partial (network refresh exists) |
| Explicit pin revocation list in profile | Not implemented |
| Compromise playbook in homelab-relay.md | TODO |
| Tests: pin rotation without re-pair | **Partial** — `test_tls_pin_rotation.py` |

## References

- [homelab-relay.md](../homelab-relay.md)
- [SECURITY_BACKLOG.md](../SECURITY_BACKLOG.md) P0-9
- [tls-endpoints.md](./tls-endpoints.md)
