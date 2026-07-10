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
| Ephemeral relay presence (location hints) | Implemented | [presence-minimal.md](./presence-minimal.md) |
| Pairing-anchored TLS (HTTPS required) | Implemented | [tls-endpoints.md](./tls-endpoints.md) |
| Queued delivery receipts (`yakr receipts flush`) | Implemented | CLI + `pending_receipts` store |
| Production receipt retry on relay down | **Implemented** (CLI) | `yakr receipts flush` |

**Testkit:** 95+ pytest tests passing (`packages/yakr-testkit/tests/`, excluding mobile CLI integration).

**Homelab Charlie:** deploy with HTTPS via `scripts/deploy_charlie_vps.sh` + `CHARLIE_TLS_DIR` (see [demo-vps-charlie.md](../demo-vps-charlie.md)).

## Charlie mesh topology (test harness)

The mesh stress tests mirror the **VPS trust model**:

| Link | Setup |
|------|--------|
| Alice ↔ Bob | Invite rendezvous on Charlie relay (production path) |
| Alice ↔ Charlie operator | Operator contact + Charlie delivery profile |
| Alice ↔ Dennis operator | Operator contact + Dennis delivery profile |
| Bob ↔ relay operators | **None** — Bob learns Charlie/Dennis TLS pins from Alice's signed profile |
| Charlie ↔ Dennis operators | **None** — not paired with each other |

Messaging is Alice ↔ Bob and Alice ↔ Charlie (operator as peer). There is no Bob ↔ Charlie shortcut.

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

# Homelab (real CHARLIE_URL + DENNIS_URL, operator homes must match deployed TLS)
export CHARLIE_URL=https://YOUR_VPS:8090
export DENNIS_URL=https://YOUR_VPS:8091
export CHARLIE_OPERATOR_HOME=/path/to/charlie-operator
export DENNIS_OPERATOR_HOME=/path/to/dennis-operator
uv run pytest packages/yakr-testkit/tests/test_homelab_mesh.py -m homelab -v

# Homelab full stress (110 messages)
uv run python scripts/stress_charlie_mesh.py --live
```

### Hybrid homelab stress (Alice ↔ Bob, 100 messages)

Exercises **Charlie + Dennis single-hop failover**, random burst sends, and concurrent **fetch-all** polling every 1–3s. Success requires matching chat histories in send order and zero pending receipts. Sender fallbacks use only relays the peer has acknowledged (pairing or profile push + receipt).

| Peer | Role | Simulated | Live |
|------|------|-----------|------|
| Alice | Client | Local tmp home | Local tmp home |
| Charlie | Relay (`both`) | In-process | `CHARLIE_URL` or local container |
| Bob | Client | Local tmp home | Local tmp home |
| Dennis | Relay (`both`) | In-process | `DENNIS_URL` (homelab container) |

Trust model: Alice paired with Charlie + Dennis; Bob paired with Dennis only (learns Charlie via Alice profile).

```bash
# Simulated (CI / no homelab) — single-hop failover across Charlie + Dennis
uv run pytest packages/yakr-testkit/tests/test_hybrid_homelab_mesh.py::test_hybrid_alice_bob_random_stress_simulated -v
uv run python scripts/hybrid_homelab_stress.py --seed 42

# Live homelab — single-hop failover (requires deployed Dennis + operator homes)
export DENNIS_URL=https://YOUR_HOMELAB:8091
export DENNIS_OPERATOR_HOME=~/.yakr/dennis
export DENNIS_WRAP_SECRET=...
# optional local Charlie container instead of in-process relay:
export CHARLIE_URL=https://127.0.0.1:8090
export CHARLIE_OPERATOR_HOME=~/.yakr/charlie
export CHARLIE_WRAP_SECRET=...
uv run python scripts/hybrid_homelab_stress.py --live
uv run pytest packages/yakr-testkit/tests/test_hybrid_homelab_mesh.py -m homelab -v
```

Homelab failover test additionally needs `CHARLIE_VPS_HOST` (or `VPS_HOST`) for `docker stop yakr-charlie` via SSH.

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
- Burst sends pile up on relay; single fetch drains in seq order ([fetch-algorithm.md](./fetch-algorithm.md): sort by `stored_at`, retry on `YAKR_ERR_DUPLICATE_SEQ`)
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

When `deliver_encrypted()` fails (relay down), use `yakr resend <contact>` after the relay returns. A background worker is not yet implemented.

### 2. Receipt delivery during relay outage

CLI `fetch` queues failed delivery receipts in SQLite (`pending_receipts`). Run `yakr receipts flush` or fetch again after the relay returns. `fetch` also attempts to flush queued receipts at the start of each poll.

### 3. `YAKR_RELAY_URL` can poison delivery profiles

`build_local_profile()` reads `YAKR_RELAY_URL` from the environment. A stale env var after a relay outage can embed a dead URL in published profiles. Mesh tests clear env in fixtures; CLI users should be aware.

### 4. Re-pair required for ratchet v2

Contacts created before this work have `ratchet.version != 2`. Old volumes need re-pairing or `Contact.establish` refresh.

### 5. Stale profile URLs until presence refresh

Signed `relay_descriptors[].url` can lag behind the operator's current host. Peers learn new locations via encrypted **presence** messages on fetch (`yakr presence push` or auto fan-out on `profile publish` when URLs change). Without fresh presence, routing falls back to profile URLs.

## Recovery recipe after Charlie outage

For operators and future send-retry worker design:

```text
1. Charlie relay back up (same URL, persisted blob store)
2. Each client: fetch all contacts (send receipts)
3. Each client: drain inbound receipts (clears peer pending for delivered messages)
4. Each client: resend any remaining outbound_pending (`yakr resend`)
5. Relay operator: `yakr presence push` after IP change so peers update location cache
```

## Next work (not in this commit)

- [x] `yakr resend` / replay `outbound_pending` when relay healthy
- [x] Send failover across ordered `relay_descriptors` (Charlie → Dennis)
- [x] Mesh stress harness includes Charlie + Dennis dual relay
- [x] Minimal presence v1 (`type=presence`, `yakr presence push`, routing prefers cache)
- [x] Pairing-anchored TLS + homelab HTTPS deploy path
- [x] CLI receipt flush resilience (`yakr receipts flush`, `pending_receipts` store)
- [x] Live homelab tests (`test_homelab_mesh.py -m homelab`, `stress_charlie_mesh.py --live`)
- [x] Hybrid homelab Alice↔Bob stress (`hybrid_homelab_stress.py`, `test_hybrid_homelab_mesh.py`)
- [x] Single-hop default + profile-ack sender fallback gate
- [x] VPS trust model in testkit (no Bob↔Charlie operator shortcut)
- [ ] Multi-device identity — **deferred** ([multi-device.md](./multi-device.md); v1 = one client per identity)
