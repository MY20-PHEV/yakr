# Phase 7 — Metadata Hardening

**Protocol:** `yakr-v0.7`  
**Status:** Implemented

## Privacy Modes

| Mode | Padding | Fetch | Relay delay |
|------|---------|-------|-------------|
| fast | none | on-demand | 0s |
| balanced | 4 KiB classes | real + 3 decoy tags | 0–15s |
| high | 4/32 KiB classes | real + 7 decoy tags + dummy blobs | 5–90s |

## Commands

```bash
yakr privacy set bob --mode balanced
yakr privacy show bob
yakr privacy metrics
yakr privacy costs
```

Relay forward delay: `yakr-relay serve --forward-delay-max 15`

## Exit Criteria

- [x] Balanced mode: relay observer cannot distinguish 300 B vs 2 KiB message at ciphertext level
- [x] High mode: scripted traffic analysis test shows reduced upload/fetch correlation
- [x] Fast mode latency within 2× of Phase 5 baseline in local benchmark
- [x] Battery/bandwidth cost documented per mode (`yakr privacy costs`)
