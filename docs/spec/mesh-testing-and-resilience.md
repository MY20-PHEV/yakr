# Mesh Testing and Relay Resilience

**Protocol:** `yakr-v1.0`  
**Status:** Implemented (tests) — gaps documented below  
**Last updated:** 2026-07-07

## Where we are

Yakr now has:

| Area | Status | Spec |
|------|--------|------|
| 24h ephemeral messages | Implemented | [ephemeral-messages.md](./ephemeral-messages.md) |
| X25519 double ratchet (`ratchet.version == 2`) | Implemented | [double-ratchet.md](./double-ratchet.md) |
| Local encrypted SQLite store (no plaintext at rest) | Implemented | [ephemeral-messages.md](./ephemeral-messages.md) |
| Charlie 3-peer mesh stress harness | Implemented | this doc |
| Relay outage / flap resilience tests | Implemented | this doc |
| Automatic send retry after relay outage | **`yakr resend`** (implemented) | [relay-failover.md](./relay-failover.md) |
| Send failover across ordered relays | Implemented | [relay-failover.md](./relay-failover.md) |
| Production receipt retry on relay down | **Partial** (testkit only) | — |

**Testkit:** 81 pytest tests passing (`packages/yakr-testkit/tests/`).

**Homelab Charlie:** `http://REDACTED_TAILSCALE_IP:8090` — redeployed with current image; demo works after wiping old v0.4 volumes (`docker compose -f docker-compose.vps-charlie.yml down -v`).

## Charlie mesh topology (test harness)

The mesh stress tests use a **3-peer in-process relay** that mirrors the VPS Charlie demo with one intentional shortcut:

| Link | Setup |
|------|--------|
| Alice ↔ Bob | Invite rendezvous on Charlie relay (production path) |
| Alice ↔ Charlie | Operator contact (`Contact.establish` + Charlie delivery profile) |
| Bob ↔ Charlie | `Contact.establish` both ways — **test-only** so Charlie can message Bob directly |

In the real VPS demo, Bob has **no** Charlie contact; he routes via Alice's advertised relay in her delivery profile.

### Running tests

```bash
# Full testkit
uv run pytest packages/yakr-testkit/tests/ -q

# Happy-path load (112 messages, receipts, duplicate-fetch idempotency)
uv run pytest packages/yakr-testkit/tests/test_mesh_stress.py -v

# Relay outage / flap / concurrent failure
uv run pytest packages/yakr-testkit/tests/test_mesh_relay_outage.py -v

# Standalone runner (local in-process relay)
uv run python scripts/stress_charlie_mesh.py
```

### Key modules

| File | Purpose |
|------|---------|
| `packages/yakr-testkit/src/yakr_testkit/mesh_setup.py` | Build mesh, relay stop/start on same data dir, stress schedules |
| `packages/yakr-testkit/src/yakr_testkit/mesh_client.py` | `MeshParticipant`: send, fetch, `try_send`, `resend_pending`, receipt flush |
| `packages/yakr-testkit/tests/test_mesh_stress.py` | Volume, bursts, receipt recovery, TTL |
| `packages/yakr-testkit/tests/test_mesh_relay_outage.py` | Relay down, restart, flap, concurrent sends |
| `packages/yakr-testkit/tests/test_ephemeral_double_ratchet.py` | Ephemeral + ratchet unit/integration tests |

## What the stress tests proved

### Happy path (`test_mesh_stress`)

With Charlie relay **always up**:

- 112+ messages across Alice, Bob, Charlie — zero loss
- Burst sends pile up on relay; single fetch drains in seq order
- Delivery receipt state machine: fetch without receipts → pending; duplicate fetch empty; flush + drain clears pending
- Double ratchet v2 and 24h `valid_until` survive volume
- Second fetch on same mailbox returns nothing (idempotent)

### Relay outage (`test_mesh_relay_outage`)

| Scenario | Result |
|----------|--------|
| Relay restart (same `BlobStore` path) | Queued blobs survive; fetch works after `start_relay()` |
| Fetch while relay down | Hard failure; no corruption; succeeds after relay returns |
| Send while relay down | `outbound_pending` saved; blob **not** on relay; **no auto-resend** |
| Rapid flap (stop/start mid-send) | Some sends fail; all recover with fetch + manual `resend_pending` |
| Concurrent sends while relay down | All fail fast; recover after `resend_pending` |
| Full schedule + kill before fetch | All messages on relay; kill/resume before fetch still delivers |
| Aggressive schedule + multiple kill points | 112 messages recover with fetch, drain receipts, `resend_pending` |
| Receipts during outage | Queued in `_unreceipted`; flush retries when relay returns |
| Pairing while relay down | Fails cleanly (timeout) |

## Known gaps (do not “improve” blindly — documented intentionally)

### 1. No automatic send retry

When `deliver_encrypted()` fails (relay down), the client:

1. Already incremented `next_send_seq`
2. Saved `outbound_pending`
3. Did **not** store the ciphertext on the relay

Recovery today: `yakr pending` lists stuck messages; **no `yakr resend` command**. Testkit uses `MeshParticipant.resend_pending()` (re-encrypt + deliver, clear stale pending entry).

### 2. Receipt delivery requires live relay

Production CLI `fetch` / receipt send paths raise on connection failure. Testkit `flush_receipts()` now keeps failed receipts in `_unreceipted` for retry — this behavior is **not** yet in `yakr-cli`.

### 3. `YAKR_RELAY_URL` can poison delivery profiles

`build_local_profile()` reads `YAKR_RELAY_URL` from the environment. A stale env var after a relay outage can embed a dead URL in published profiles. Mesh tests clear env in fixtures; CLI users should be aware.

### 4. Re-pair required for ratchet v2

Contacts created before this work have `ratchet.version != 2`. Old volumes need re-pairing or `Contact.establish` refresh.

## Recovery recipe after Charlie outage

For operators and future send-retry worker design:

```text
1. Charlie relay back up (same URL, persisted blob store)
2. Each client: fetch all contacts (send receipts)
3. Each client: drain inbound receipts (clears peer pending for delivered messages)
4. Each client: resend any remaining outbound_pending (manual today)
```

## Next work (not in this commit)

- [x] `yakr resend` / replay `outbound_pending` when relay healthy
- [x] Send failover across ordered `relay_descriptors` (Charlie → Dennis)
- [x] Mesh stress harness includes Charlie + Dennis dual relay
- [ ] CLI receipt flush resilience (match testkit `_unreceipted` retry)
- [ ] Live homelab stress (`stress_charlie_mesh.py --live` wired to `CHARLIE_URL`)
- [ ] Drop Bob↔Charlie test shortcut if stress should match VPS trust model exactly
- [ ] Multi-device identity ([multi-device.md](./multi-device.md) — spec only)
