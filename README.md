# Yakr Protocol

A decentralised, social-relay, post-quantum messaging protocol — from *yakking* (talking), without a central platform.

**What makes Yakr Protocol different:** **Your relay network is your pairing graph.** End-to-end encrypted mail is stored and forwarded only on mailboxes run by people you have pairwise paired with, not on a central operator or an open global relay pool. Phones that cannot accept inbound connections (cellular, NAT, iOS) **poll outbound** to those paired relays; peers discover relay URLs and TLS pins through **signed delivery profiles** in the trust graph. Production messengers and relay hosts are independent products; this repository holds the **open spec, reference implementation, and certification program**.

Not affiliated with unrelated sound-alike businesses — see [NOTICE.md](NOTICE.md).

## Documents

| Document | Description |
|----------|-------------|
| [whitepaper.md](whitepaper.md) | Conceptual protocol whitepaper (Draft v0.1) |
| [CERTIFICATION.md](CERTIFICATION.md) | **Yakr Protocol Certified** conformance program (draft) |
| [NOTICE.md](NOTICE.md) | Name, UK IPO search summary, independence disclaimers |
| [docs/REFERENCE_DESIGN.md](docs/REFERENCE_DESIGN.md) | Phased reference implementation plan |
| [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md) | Normative v1.0 protocol spec |
| [docs/spec/relay-rendezvous.md](docs/spec/relay-rendezvous.md) | Group relay as pairing rendezvous (implemented) |
| [docs/spec/relay-authorization.md](docs/spec/relay-authorization.md) | Who may advertise which relays |
| [docs/spec/presence-v1.md](docs/spec/presence-v1.md) | Planned v1.1 presence + group relay polling |
| [docs/spec/presence-minimal.md](docs/spec/presence-minimal.md) | **Implemented** minimal presence (30m TTL location hints) |
| [docs/spec/tls-endpoints.md](docs/spec/tls-endpoints.md) | **Implemented** pairing-anchored TLS (SPKI pins in profiles) |
| [docs/spec/ephemeral-messages.md](docs/spec/ephemeral-messages.md) | 24h ephemeral message TTL |
| [docs/spec/double-ratchet.md](docs/spec/double-ratchet.md) | X25519 double ratchet |
| [docs/spec/mesh-testing-and-resilience.md](docs/spec/mesh-testing-and-resilience.md) | Mesh stress and relay outage test status |
| [docs/html/index.html](docs/html/index.html) | Visual protocol guide (HTML + flowcharts) |
| [docs/demo-vps-charlie.md](docs/demo-vps-charlie.md) | Alice/Bob local + Charlie on VPS demo |

## Status

**Phase 10 complete** — Yakr Protocol v1.0, test vectors, security analysis, interop verifier, presence/TLS/failover, `yakr fetch --all`, and relay embed (see [docs/spec/phase-10-presence.md](docs/spec/phase-10-presence.md)).

**Steward model:** open spec and reference code; third parties ship messengers and relay hosting. [CERTIFICATION.md](CERTIFICATION.md) describes the **Yakr Protocol Certified** program (applications not yet open).

| Document | Description |
|----------|-------------|
| [CERTIFICATION.md](CERTIFICATION.md) | Certified client/relay program and badge rules |
| [interop/README.md](interop/README.md) | Third-party self-test checklist |

## Quick Summary

**Yakr Protocol** delivers end-to-end encrypted messages through **pairing-gated social relays** — friends' VPS, homelab, or org-operated mailboxes — with **no central message server** and no requirement that both peers be online at once.

```text
Alice encrypts → paired relay stores opaque blob → offline Bob polls outbound to fetch
```

Implementers: see [interop/README.md](interop/README.md) and [CERTIFICATION.md](CERTIFICATION.md).

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

## Docker Demos (recommended)

Spin up isolated client identities with persistent volumes:

```bash
./scripts/demo_offline_delivery.sh       # Phase 1 single-hop
./scripts/demo_two_hop_delivery.sh       # Phase 2 two-hop + receipts
./scripts/demo_invite_pairing.sh         # Phase 4 invite pairing + tickets
./scripts/demo_profile_delivery.sh       # Phase 5 delivery profiles + direct P2P
./scripts/demo_hybrid_pairing.sh         # Phase 6 hybrid PQ pairing
./scripts/demo_relay_group_pairing.sh    # Relay rendezvous (local Charlie)
```

### Alice + Bob local, Charlie on a VPS

```bash
# 1. Deploy relay to your server (default port 8090)
VPS_HOST=user@YOUR_HOST ./scripts/deploy_charlie_vps.sh

# 2. Run pairing + messaging demo from your laptop
export CHARLIE_URL=http://YOUR_HOST:8090
./scripts/demo_vps_charlie_relay.sh
```

See [docs/demo-vps-charlie.md](docs/demo-vps-charlie.md) for details. Alice must be paired with the Charlie relay operator; Bob pairs via Charlie rendezvous without advertising Charlie in his profile.

## Interop (Phase 9)

```bash
uv run pytest packages/yakr-testkit/tests/test_phase9_interop.py -q
uv run pytest packages/yakr-testkit/tests/test_phase9_relay_abuse.py -q
```

## Android (Phase 8)

```bash
cd apps/yakr-android && briefcase build android
```

See [apps/yakr-android/README.md](apps/yakr-android/README.md).

## Manual Docker steps

```bash
docker compose build
docker compose up -d relay
docker compose run --rm setup

docker compose run --rm --no-deps alice send bob "hello"
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

## Relay rendezvous CLI (quick reference)

```bash
# Alice invites Bob via group relay
yakr invite create --rendezvous https://relay.example:8090 --no-wait
yakr invite relay wait

# Bob accepts (no pairing with relay operator required)
yakr invite accept "yakr://invite/..." --name alice
```

## License

TBD
