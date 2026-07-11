# Minimal presence v1

Ephemeral relay **location** separate from signed **identity** in delivery profiles.

## Problem

`relay_descriptors[].url` in signed profiles (7-day TTL) is the wrong layer for:

- Opportunistic relays (any paired operator can relay)
- IP / host changes without re-signing and re-pushing full profiles

## Layers

| Layer | Carries | TTL |
|-------|---------|-----|
| **Profile** | Relay identity: `name`, `wrap_secret`, `role` | days (signed) |
| **Presence** | Location: `operator_name`, `reachable_url`, `relay_active`, `valid_until` | 30 minutes |

Profile URLs remain as **legacy hints** when no fresh presence exists.

## Payload

Protocol: `yakr-v1.1/presence`

```json
{
  "protocol": "yakr-v1.1/presence",
  "operator_name": "charlie",
  "reachable_url": "https://relay.example:8090",
  "relay_active": true,
  "valid_until": 1710000000000
}
```

Transport: encrypted inner message `type=presence` (same ratchet channel as text/profile).

## Security

- Only accept presence where `operator_name` matches the **paired contact name** (the operator who signed it).
- Ignore expired or `relay_active=false` hints.
- Presence does not replace wrap secrets or roles — only the reachable URL.

## Routing

When resolving a relay URL (send, fetch, tickets):

1. Fresh presence cache for `operator_name`
2. Else profile `relay_descriptors[].url`

Implemented in `resolve_operator_url()` and wired through `delivery_mailbox_urls` / `fetch_mailbox_urls`.

## Operator workflow

On relay host / port change:

1. `yakr profile publish` (updates signed profile; auto fan-out presence when URLs change)
2. Or `yakr presence push` to fan out current location immediately

Recipients learn on **fetch** (mailbox poll), not inbound push — NAT-safe. Phones on cellular do not become inbound-reachable mailboxes; friend-operator relays remain the correctness path. See [ADR 008](../adr/008-nat-reachability-and-mobile-delivery.md). Optional silent platform wake (opt-in) may trigger fetch sooner without changing the relay store-and-forward model — [ADR 011](../adr/011-optional-platform-wake.md).

## Charlie → Dennis → Alice

Charlie can post presence to Dennis's mailbox; Alice polls Dennis (listed in her profile). Send failover tries Charlie then Dennis; presence updates propagate the same path.

## CLI

```bash
yakr presence push [contact]   # fan-out to all paired contacts (or one)
yakr presence show [operator]  # show cached hints
yakr fetch --all               # poll all contacts + trust-graph relays
yakr relay embed               # foreground embedded relay (ADR 008 dialability)
```

## See also

- [relay-failover.md](./relay-failover.md)
- [presence-v1.md](./presence-v1.md) — fuller future design
