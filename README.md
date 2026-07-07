# Yakr

A decentralised, social-relay, post-quantum messaging protocol.

## Documents

| Document | Description |
|----------|-------------|
| [whitepaper.md](whitepaper.md) | Conceptual protocol whitepaper (Draft v0.1) |
| [docs/REFERENCE_DESIGN.md](docs/REFERENCE_DESIGN.md) | Phased reference implementation plan |

## Status

**Phase 0** — Protocol sketch complete. Phase 1 (single-hop offline delivery CLI) not yet started.

## Quick Summary

Yakr delivers end-to-end encrypted messages through a user's trusted contact relay network — no central message server, no requirement that both peers be online at the same time.

```text
Alice encrypts → friend relay stores opaque blob → offline Bob fetches later
```

## Repository Structure (Planned)

Python monorepo (uv workspace):

```text
packages/yakr-core/     protocol and crypto library
packages/yakr-relay/    relay daemon (FastAPI)
packages/yakr-cli/      command-line reference client (Typer)
packages/yakr-testkit/  test harness and demos (pytest)
```

Implementation language: **Python 3.12+**

## License

TBD
