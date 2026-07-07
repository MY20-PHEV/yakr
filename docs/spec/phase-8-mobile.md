# Phase 8 — Mobile Reference Client (Android)

**Protocol:** `yakr-v1.0` (candidate freeze)  
**Status:** Implemented (reference scaffold)

## Goal

Prove Yakr works on a mobile device with offline delivery, invite QR, and optional relay participation.

## Package Layout

```text
packages/yakr-mobile/     Mobile client library (encrypted store, workers, QR)
apps/yakr-android/      BeeWare Briefcase Android shell
```

## Features

- **Encrypted SQLite store** — passphrase-wrapped Fernet encryption over identity/contacts
- **YakrMobileClient** — send, fetch, invite QR, pairing, resume after process death
- **FetchWorker** — battery-aware poll intervals (30s charging / 300s battery / 900s low battery)
- **RelayWorker** — respects Wi-Fi-only and charging-only gates
- **Toga UI** — contact list, chat, invite safety code display

## Build APK

See [apps/yakr-android/README.md](../../apps/yakr-android/README.md).

## Exit Criteria

- [x] Two mobile clients exchange messages with relay (simulated offline delivery)
- [x] QR invite payload generation with safety code
- [x] Relay mode respects Wi-Fi/charging constraints
- [x] App survives process death; messages and worker state persist
