# Yakr Android (Briefcase)

BeeWare Briefcase shell for the Phase 8 mobile reference client.

## Prerequisites

- Python 3.12+
- [Android SDK](https://developer.android.com/studio) with `ANDROID_HOME` set
- Briefcase: `pip install briefcase`

## Build sideload APK

```bash
cd apps/yakr-android
briefcase create android
briefcase build android
briefcase package android
```

## Run on emulator

```bash
briefcase run android
```

Point the app relay URL at the host machine (`http://10.0.2.2:8080` from the Android emulator).

## Architecture

```text
Toga UI (yakr_mobile.toga_app)
    → YakrMobileClient
        → MobileStore (encrypted SQLite)
        → yakr-core (crypto, sessions, invites)
```

Background fetch and relay workers are implemented in `yakr_mobile.client` and intended to run via Android WorkManager / foreground service in a full deployment.
