# Yakr

A decentralised, social-relay, post-quantum messaging protocol.

## Documents

| Document | Description |
|----------|-------------|
| [whitepaper.md](whitepaper.md) | Conceptual protocol whitepaper (Draft v0.1) |
| [docs/REFERENCE_DESIGN.md](docs/REFERENCE_DESIGN.md) | Phased reference implementation plan |
| [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md) | Normative v1.0 protocol spec |
| [docs/spec/presence-v1.md](docs/spec/presence-v1.md) | Planned v1.1 presence + group relay polling |
| [docs/html/index.html](docs/html/index.html) | Visual protocol guide (HTML + flowcharts) |

## Status

**Phase 9 complete** — Yakr Protocol v1.0 frozen with test vectors, security analysis, and interop verifier.

| Document | Description |
|----------|-------------|
| [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md) | Normative v1.0 protocol spec |
| [docs/spec/test-vectors-v1/](docs/spec/test-vectors-v1/) | Interop test vectors |
| [docs/security/analysis-v1.md](docs/security/analysis-v1.md) | Threat model and mitigations |
| [interop/README.md](interop/README.md) | Third-party client checklist |
| [docs/html/index.html](docs/html/index.html) | Visual protocol guide (HTML + flowcharts) |

## Quick Summary

Yakr delivers end-to-end encrypted messages through a user's trusted contact relay network — no central message server, no requirement that both peers be online at the same time.

```text
Alice encrypts → friend relay stores opaque blob → offline Bob fetches later
```

## Repository Structure

Python monorepo (uv workspace):

```text
packages/yakr-core/     protocol and crypto library
packages/yakr-relay/    relay daemon (FastAPI)
packages/yakr-cli/      command-line reference client (Typer)
packages/yakr-testkit/  test harness and demos (pytest)
packages/yakr-mobile/   Android/mobile reference client
apps/yakr-android/      BeeWare Briefcase APK shell
```

## Docker Demo (recommended)

Spin up isolated client identities with persistent volumes — easiest way to test multi-party flows:

```bash
./scripts/demo_offline_delivery.sh      # Phase 1 single-hop
./scripts/demo_two_hop_delivery.sh      # Phase 2 two-hop + receipts
./scripts/demo_invite_pairing.sh        # Phase 4 invite pairing + tickets
./scripts/demo_profile_delivery.sh      # Phase 5 delivery profiles + direct P2P
./scripts/demo_hybrid_pairing.sh          # Phase 6 hybrid PQ pairing

## Interop (Phase 9)

```bash
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q
```

See [interop/README.md](interop/README.md) and [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md).

## Android (Phase 8)

```bash
cd apps/yakr-android && briefcase build android
```

See [apps/yakr-android/README.md](apps/yakr-android/README.md).
```

Manual steps:

```bash
docker compose build
docker compose up -d relay
docker compose run --rm setup

# Alice sends while Bob is offline
docker compose run --rm --no-deps alice send bob "hello"

# Bob fetches later
docker compose run --rm --no-deps bob fetch alice
```

Each client (`alice`, `bob`, `charlie`, `dennis`) is the same image with a separate data volume and `YAKR_NAME` set.

## Local Development

```bash
uv sync --all-packages
uv run pytest

# Terminal 1: relay
uv run yakr-relay serve --port 8080 --data-dir ./data/relay

# Terminal 2: alice
export YAKR_HOME=./data/alice YAKR_NAME=alice YAKR_RELAY_URL=http://127.0.0.1:8080
uv run yakr init --name alice --force
uv run yakr export-public

# Terminal 3: bob
export YAKR_HOME=./data/bob YAKR_NAME=bob YAKR_RELAY_URL=http://127.0.0.1:8080
uv run yakr init --name bob --force
uv run yakr contact-add alice ./data/alice/public.json
uv run yakr fetch alice
```

## License

TBD
