# Rust port progress

Status as of **2026-07-11**. Goal: a second reference implementation that speaks the same wire formats as the Python stack (`packages/yakr-*`), verifiable against `docs/spec/test-vectors-v1/` and interoperable in live mesh tests.

**Phase 11 WP1 (Option B pairing/ratchet):** Rust `yakr-core` now matches Python normative pairing path — transcript includes ratchet publics, joiner `pairing_recv_init`, inviter deferred `pairing_send_init` on first encrypt, decrypt rollback, skip limits.

## Quick commands

```bash
cd rust
cargo test              # 14 tests across all crates
cargo build --release   # yakr, yakr-relay binaries

# Relay
./target/release/yakr-relay --listen 127.0.0.1:8080 --data-dir /tmp/yakr-relay

# Client (needs identity + paired contact on disk)
export YAKR_HOME=~/.yakr/alice   # or pass --home on each command
./target/release/yakr init --name alice
./target/release/yakr show
./target/release/yakr send bob "hello" --relay http://127.0.0.1:8080
./target/release/yakr fetch bob --relay http://127.0.0.1:8080
```

CI: `.github/workflows/ci.yml` runs `cargo test` in `rust/` on every push/PR.

## Workspace map

| Rust crate | Python package | Purpose |
|------------|----------------|---------|
| `yakr-crypto` | `yakr_core.crypto`, interop vectors | HKDF, X25519, XChaCha20-Poly1305, vector conformance |
| `yakr-core` | `yakr_core` | Identity, pairing, double ratchet, session, store |
| `yakr-relay` | `yakr_relay` | Mailbox blob store + HTTP API |
| `yakr-cli` | `yakr_cli` (subset) | Reference CLI binary `yakr` |

Interop checklist: [`interop/README.md`](../interop/README.md) — almost all Rust items are checked.

## Commit history (Rust work)

| Commit | Summary |
|--------|---------|
| `08c8962` | Scaffold `yakr-crypto` + hybrid KEX + mailbox tag vectors + CI |
| `3b87bf5` | Inner message canonical JSON |
| `e6af3fc` | Invite bundle verify + safety code |
| `9f4d4de` | Delivery profile verify |
| `033b4b1` | X25519, classical master/message keys, XChaCha AEAD |
| `b0146fb` | **`yakr-core`**: ratchet, pairing, session, identity/store |
| `8ffa2e8` | **`yakr-relay`**: BlobStore + axum + abuse tests |
| `9fe6cfd` | **`yakr-cli`**: init/show/export-public/send/fetch + full-workspace CI |

## Per-crate detail

### `yakr-crypto` — DONE (vectors + primitives)

**Modules:** `hkdf`, `hybrid`, `mailbox`, `master`, `x25519`, `aead`, `inner_message`, `invite`, `delivery_profile`, `cbor`, `encoding`

**Tests (8):** all five `docs/spec/test-vectors-v1/*.json` files + inner-message AEAD round-trip.

**Key deps:** `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `ciborium`, `hkdf`, `hmac`, `sha2`

**Interop notes:**
- CBOR unsigned payloads for invite/profile must match Python `cbor2` byte-for-byte (map key order matters). Regression tests pin expected hex from Python.
- Inner message JSON uses `serde_json` → `Value` re-serialize for sorted compact form (`sort_keys` equivalent).

---

### `yakr-core` — CORE PATH DONE; advanced features missing

**Modules:**

| Module | Python equivalent | Status |
|--------|-------------------|--------|
| `ratchet` | `ratchet.py` | ✅ X25519 double ratchet v2, encrypt/decrypt, persist as JSON |
| `session` | `session.py` | ✅ `encrypt_text`, `decrypt_outer`, privacy padding (fast mode) |
| `pairing` | `pairing.py` | ✅ classical + hybrid pair-master, inviter/joiner complete |
| `invite` | `invite.py` | ✅ `create_invite`, verify; CBOR sign |
| `identity` | `identity.py` | ✅ generate, save/load JSON, `Contact` establish_classical |
| `store` | `store.py` | ⚠️ identity + contacts JSON only (no SQLite messages DB) |
| `mailbox` | `mailbox.py` | ✅ `MailboxTagDeriver`, `candidate_epochs` |
| `hybrid_pq` | `hybrid_pq.py` | ✅ ML-KEM-768 via `ml-kem` crate (expanded 2400-byte secret keys, matching Python `pqcrypto`) |
| `privacy` | `privacy.py` | ⚠️ pad/unpad only; no decoy tags or dummy blobs |
| `ephemeral` | `ephemeral.py` | ✅ message TTL enforcement |
| `message` | `message.py` | ✅ `OuterBlob` relay JSON; re-exports `InnerMessage` from crypto |
| `error` | `errors.py` | ⚠️ subset of error types |

**Tests (5)** in `yakr-core` (lib + `tests/session.rs`):
- `pairing_transcript_vectors` — classical + hybrid `pairing_transcript.json`
- `pairing_path_rotates_dh_epoch` — Option B DH epoch on first traffic
- `double_ratchet_bootstrap_vector` — `double_ratchet.json`
- `double_ratchet_bidirectional` — Alice→Bob→Alice encrypt/decrypt
- `ratchet_state_persists_via_store` — contact JSON round-trip, ratchet version 2
- `mailbox_epoch_lookback` — 3 candidate epochs (lookback=2)

**Not ported from `yakr_core`:**
- `delivery_profile` create/publish/verify (verify only in crypto)
- `relay_ticket`, `relay_authorization`, `relay_operator`, `relay_deploy`
- `routing`, `http_client`, `tls` (SPKI pinning)
- `presence`, `profile_ack`
- `onion` (legacy two-hop)
- `store` SQLite (`messages.db`), outbound pending, receipts queue, route state
- Full `Session`: receipts, profiles, presence encrypt paths
- `privacy` balanced/high modes with decoy fetch tags

---

### `yakr-relay` — MINIMAL MAILBOX DONE

**Implemented:**
- `BlobStore` — SQLite `relay.db`, 32-byte tag, expiry, 64 KiB max, 256 blobs/tag, 24h TTL cap
- HTTP: `GET /healthz`, `POST /v1/blobs`, `GET /v1/blobs/{tag}`
- Binary: `yakr-relay serve` (clap: `--listen`, `--name`, `--data-dir`)

**Tests (3)** in `yakr-relay/tests/abuse.rs` — mirrors `test_phase9_relay_abuse.py` (subset).

**Not implemented:**
- Pairing rendezvous (`/v1/pair*`, `PairingStore`)
- Entry relay role, onion ingest, relay tickets, forward delay
- `POST /v1/relay`, `/v1/ingest`
- Oversized-blob **test** (store logic rejects >64 KiB; no dedicated test yet)

---

### `yakr-cli` — MINIMAL CLIENT DONE

**Commands:**

| Rust | Python `yakr` | Notes |
|------|---------------|-------|
| `init --name` | `init` | hybrid PQ keys generated by default |
| `show` | `show` | name + device_id |
| `export-public` | `export-public` | prints `public.json` |
| `send CONTACT MSG` | `send` | encrypt + POST to relay |
| `fetch CONTACT` | `fetch` | epoch lookback (2) + decrypt |

**Env:** `YAKR_HOME` or `~/.yakr/<name>`, `YAKR_NAME`, `--relay` (default `http://127.0.0.1:8080`)

**Not implemented:** entire `invite`, `profile`, `presence`, `receipts`, `privacy`, `relay` subcommand trees; `fetch --all --wide`; `pending`/`resend`; `contact-add` (can use Python or manual JSON); offline QR pairing.

---

## End-to-end path today

What works in Rust alone (after a contact exists):

1. `Identity::generate` → save to `identity.json` + `public.json`
2. Pairing via **`yakr-core` API** (`create_invite` → `build_pairing_request` → `inviter_complete_pairing` / `joiner_complete_pairing`) — tested in unit tests, **not yet exposed in CLI**
3. `Session::encrypt_text` → double ratchet → `OuterBlob` → POST `/v1/blobs`
4. `fetch` with `MailboxTagDeriver::candidate_epochs(lookback=2)` → GET blobs → `Session::decrypt_outer`

**Practical gap:** to pair two Rust identities without Python, you need either CLI `invite` commands or a small pairing example binary. Contacts can be created by pairing in Python and copying `contacts/*.json` into the Rust `YAKR_HOME` tree (same on-disk layout).

## Python ↔ Rust interop smoke test (manual)

```bash
# Terminal 1: Rust relay
cd rust && cargo run -p yakr-relay -- --listen 127.0.0.1:8099 --data-dir /tmp/rust-relay

# Terminal 2: Python client (existing paired alice/bob from ~/.yakr)
YAKR_RELAY_URL=http://127.0.0.1:8099 uv run yakr send bob "from python" ...
YAKR_HOME=~/.yakr/bob YAKR_RELAY_URL=http://127.0.0.1:8099 \
  ./rust/target/release/yakr fetch alice --relay http://127.0.0.1:8099
```

Reverse direction (Rust send → Python fetch) should work if contact ratchet state is compatible (same pairing).

## Implementation pitfalls (read before continuing)

1. **CBOR map order** — Python `cbor2.dumps` preserves insertion order. Use `ciborium` with ordered map entries; pin hex in tests when changing invite/profile encoding.
2. **ML-KEM secret keys** — Python `pqcrypto` uses 2400-byte expanded decapsulation keys. Rust `ml-kem` 0.3 prefers 64-byte seeds; we use deprecated `from_expanded_bytes` for wire compatibility.
3. **Ratchet header** — magic `YKDR2`, 32-byte DH public, `>II` prev_n/message_n, then XChaCha ciphertext. Must match `packages/yakr-core/src/yakr_core/ratchet.py` exactly.
4. **Inner message JSON** — field order is lexicographic; `message_id: null` must be present when null (Python `asdict`).
5. **Temp dirs in tests** — keep `tempfile::TempDir` alive for SQLite relay tests (dropping dir early breaks `relay.db`).

## Recommended next steps (priority order)

### P0 — Usable Rust-only demo
1. **`yakr invite create` / `invite accept`** in CLI (wire to existing `yakr-core` pairing)
2. **`contact-add`** from `public.json` or classical establish
3. **Integration test**: Rust Alice pairs Rust Bob → send → fetch round-trip via in-process relay

### P1 — CLI parity (high-value commands)
4. `fetch --all`, wide trust-graph poll (needs delivery profiles + routing)
5. `profile publish` / `push`, `presence push`
6. `receipts flush`, `pending` / `resend`
7. SQLite message store in `yakr-core` (port `FileLocalStore` message tables)

### P2 — Relay parity
8. Pairing rendezvous endpoints (`PairingStore`)
9. Relay tickets + entry/mailbox roles
10. Oversized blob interop test

### P3 — Certification / mesh
11. Port key tests from `packages/yakr-testkit/tests/test_ephemeral_double_ratchet.py`, `test_phase6_hybrid.py`
12. Rust↔Python five-peer mesh subset (Charlie relay + Rust client)
13. TLS SPKI pinning HTTP client

### P4 — Optional
14. `yakr-mobile` equivalent (out of scope unless product needs it)
15. Privacy modes balanced/high with decoy tags

## File index

```
rust/
├── Cargo.toml              # workspace: crypto, core, relay, cli
├── RUST_PORT.md            # this file
├── yakr-crypto/src/        # 11 modules — vectors + crypto primitives
├── yakr-core/src/          # 12 modules — protocol library
├── yakr-core/tests/session.rs
├── yakr-relay/src/         # store, app, main
├── yakr-relay/tests/abuse.rs
└── yakr-cli/src/main.rs    # single-file CLI (candidates for split)
```

## Related docs

- Spec: `docs/spec/yakr-protocol-v1.md`
- Vectors: `docs/spec/test-vectors-v1/`
- Interop checklist: `interop/README.md`
- Python reference layout: `docs/REFERENCE_DESIGN.md`
- Certification requirements: `CERTIFICATION.md`
