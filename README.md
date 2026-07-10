# Yakr Protocol

A decentralised, social-relay, post-quantum messaging protocol — from *yakking* (talking), without a central platform.

**What makes Yakr Protocol different:** **Your relay network is your pairing graph.** End-to-end encrypted mail is stored and forwarded only on mailboxes run by people you have pairwise paired with, not on a central operator or an open global relay pool. Phones that cannot accept inbound connections (cellular, NAT, iOS) **poll outbound** to those paired relays; peers discover relay URLs and TLS pins through **signed delivery profiles** in the trust graph. Production messengers and relay hosts are independent products; this repository holds the **open spec, reference implementation, and certification program**.

Not affiliated with unrelated sound-alike businesses — see [NOTICE.md](NOTICE.md).

**Web:** [yakr.co.uk](https://yakr.co.uk) (registered; DNS pending) · Merch: [yakr.store](https://yakr.store) (future) · **Source:** [github.com/MY20-PHEV/yakr](https://github.com/MY20-PHEV/yakr)

> **Project maturity:** Reference implementation phases are largely complete; **protocol stability is draft** and **security maturity is experimental** (no external audit; not recommended for production). See [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) and [SECURITY.md](SECURITY.md).

## Document precedence

When documents disagree, use this order (highest first):

1. [docs/spec/yakr-protocol-v1.md](docs/spec/yakr-protocol-v1.md) — normative v1.0 wire protocol
2. Normative extension specifications under `docs/spec/` (fetch algorithm, delivery state machine, TLS, etc.)
3. Published errata (when issued)
4. Frozen test vectors under `docs/spec/test-vectors-v1/`
5. [docs/REFERENCE_DESIGN.md](docs/REFERENCE_DESIGN.md) — phased implementation plan
6. [whitepaper.md](whitepaper.md) and implementation history / ADRs

The whitepaper explains intent; the normative spec determines interoperability.

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
| [docs/spec/fetch-algorithm.md](docs/spec/fetch-algorithm.md) | **Normative** fetch ordering, receipts, and contact state |
| [docs/spec/delivery-state-machine.md](docs/spec/delivery-state-machine.md) | Delivery/receipt state machine (P0 draft) |
| [docs/SECURITY_BACKLOG.md](docs/SECURITY_BACKLOG.md) | Security hardening backlog (P0–P3) |
| [docs/target-audience.md](docs/target-audience.md) | Target audience and positioning (draft) |
| [docs/reviews/external-critique-2026-07-10.md](docs/reviews/external-critique-2026-07-10.md) | External protocol review (reference) |
| [docs/reviews/github-follow-up-critique-2026-07-10.md](docs/reviews/github-follow-up-critique-2026-07-10.md) | Follow-up review after GitHub publication |
| [docs/spec/double-ratchet.md](docs/spec/double-ratchet.md) | X25519 double ratchet |
| [docs/spec/mesh-testing-and-resilience.md](docs/spec/mesh-testing-and-resilience.md) | Mesh stress and relay outage test status |
| [docs/html/index.html](docs/html/index.html) | Visual protocol guide (HTML + flowcharts) |
| [docs/demo-vps-charlie.md](docs/demo-vps-charlie.md) | Alice/Bob local + Charlie on VPS demo |
| [docs/homelab-relay.md](docs/homelab-relay.md) | **Homelab relay runbook** — 8090 at home, Tailscale, or VPS |

## Relay operator CLI

```bash
yakr relay create alice-ops --public-url https://relay.example:8090   # operator identity + pairing
yakr relay deploy alice-ops --vps user@203.0.113.10                   # VPS via deploy script
yakr relay status alice-ops
yakr profile publish && yakr profile push bob
```

See [docs/homelab-relay.md](docs/homelab-relay.md).

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

## Relay-less peers (first-class)

**You do not need to run a relay to use Yakr.** Many users are phone-only:

```text
Bob pairs with Alice (and maybe Geoff). He never runs yakr-relay or port-forwards at home.

Bob → Alice:  POST to relays in Alice's signed profile (e.g. her homelab :8090)
Alice → Bob:  POST to Bob's mailboxes, or her paired relay as sender fallback
Bob fetch:    yakr fetch alice  — polls Bob's mailboxes + Alice's profile relays only
```

Bob learns relay URLs and TLS pins from **contacts' signed profiles** (transitive trust). He does not pair with every operator in the cell. When Bob invites **Geoff**, and Geoff advertises his own relay, Bob talks to both without ever operating infra.

**Someone in the cell** usually opts in as **relay operator** (homelab `:8090`, Tailscale, or a small VPS) — see [docs/homelab-relay.md](docs/homelab-relay.md). That is a separate role from “second device”; v1 is one messaging client per identity.

## Repository Structure

Python monorepo (uv workspace) plus an independent Rust crypto reference:

```text
packages/yakr-core/     protocol and crypto library
packages/yakr-relay/    relay daemon (FastAPI)
packages/yakr-cli/      command-line reference client (Typer)
packages/yakr-testkit/  test harness and demos (pytest)
packages/yakr-mobile/   Android/mobile reference client
apps/yakr-android/      BeeWare Briefcase APK shell
rust/                   Rust reference stack (yakr-crypto, yakr-core, yakr-relay, yakr-cli)
```

## Docker Demos (recommended)

Spin up isolated client identities with persistent volumes:

```bash
./scripts/demo_offline_delivery.sh       # Phase 1 single-hop
./scripts/demo_two_hop_delivery.sh       # Phase 2 onion wire demo (legacy; CLI uses single-hop)
./scripts/demo_invite_pairing.sh         # Phase 4 invite pairing + tickets
./scripts/demo_profile_delivery.sh       # Phase 5 delivery profiles + direct P2P
./scripts/demo_hybrid_pairing.sh         # Phase 6 hybrid PQ pairing
./scripts/demo_relay_group_pairing.sh    # Relay rendezvous (local Charlie)
uv run python scripts/hybrid_homelab_stress.py   # 100-msg Alice↔Bob hybrid stress
uv run python scripts/stress_charlie_mesh.py    # Charlie mesh stress
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

| Material | Licence |
|----------|---------|
| Reference implementation (`packages/`, `rust/`, `apps/`, etc.) | [Apache-2.0](LICENSE) |
| Specifications and documentation (`docs/`, `whitepaper.md`) | [CC BY 4.0](docs/DOCUMENTATION-LICENSE.md) |

See [NOTICE.md](NOTICE.md) for naming and independence disclaimers.

