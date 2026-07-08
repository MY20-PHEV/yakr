# Relay Failover — Ordered Mailbox Attempts

**Protocol:** `yakr-v1.0`  
**Status:** Implemented

## Policy

When delivering a message (single-hop, no explicit `--route`):

1. Try **direct hints** on the recipient profile (if allowed). Best-effort only — fails on NAT’d mobile without same-LAN, IPv6, or hole punch. See [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md).
2. Build an **ordered URL list**:
   - Recipient `relay_descriptors` with role `mailbox` or `both` (profile order).
   - Then sender's own published mailboxes **that the recipient has acknowledged**
     (pairing snapshot or profile push + receipt), deduplicated.
3. `POST /v1/blobs` to each URL in order until one succeeds.
4. If all fail, raise and leave `outbound_pending` for `yakr resend`.

Legacy two-hop routes (`--route entry,mailbox`) parse the **mailbox** name only;
the reference client does not forward through entry relays.

## Profile acknowledgement (sender fallback gate)

Each contact record stores `peer_acked_my_profile_version` and
`peer_acked_my_relay_names`. A sender fallback relay is used only when its
operator name appears in that set. This guarantees **send ⊆ fetch**: mail is
not stored on a relay the recipient cannot poll yet.

Workflow when adding relay operator Eve:

```bash
yakr profile publish          # local profile vN includes Eve
yakr profile push bob         # encrypted profile; pending until receipt
# Bob fetches, applies profile, sends receipt
# Alice fetch/drain updates peer_acked → Eve eligible for fallback
```

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
