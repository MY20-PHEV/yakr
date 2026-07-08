# Relay Failover — Ordered Mailbox Attempts

**Protocol:** `yakr-v1.0`  
**Status:** Implemented

## Policy

When delivering a message (single-hop, no explicit `--route`):

1. Try **direct hints** on the recipient profile (if allowed). Best-effort only — fails on NAT’d mobile without same-LAN, IPv6, or hole punch. See [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md).
2. Build an **ordered URL list**:
   - Recipient `relay_descriptors` with role `mailbox` or `both` (profile order).
   - Then sender's own published mailboxes (paired operators), deduplicated.
3. `POST /v1/blobs` to each URL in order until one succeeds.
4. If all fail, raise and leave `outbound_pending` for `yakr resend`.

Two-hop routes (`--route entry,mailbox` or auto-selected onion path) still use a **single** path per message.

## Fetch (unchanged)

Fetch polls mailbox URLs outbound. Recipients do **not** need inbound connectivity — this is the mobile/cellular correctness path.

Fetch polls **all** mailbox URLs (sender + recipient profile union). Failover on send does not duplicate blobs across relays.

Clients MUST sort and retry blob decrypt per [fetch-algorithm.md](./fetch-algorithm.md). Relay `stored_at` order is not guaranteed to match application `seq`.

## Recovery

```bash
yakr resend bob   # re-encrypt and deliver all pending outbound to bob
```

## Profile ordering

`relay_descriptors` order is preference order: first relay is tried first on send. Peers should list their most preferred / closest relay first.

## Homelab

Alice may be paired with **Charlie** (primary) and **Dennis** (secondary). Set `DENNIS_URL` in VPS demo setup so Alice's profile lists both. When Charlie is down, sends fail over to Dennis automatically.

See [mesh-testing-and-resilience.md](./mesh-testing-and-resilience.md) for stress test coverage.
