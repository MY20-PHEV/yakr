# VPS Charlie demo (Alice + Bob local, Charlie on VPS)

Alice and Bob run in **local Docker containers**. Charlie is a `yakr-relay` on your VPS (pairing rendezvous + message store).

Alice is pre-paired with the Charlie relay operator. Bob is not.

## 1. Deploy Charlie on your VPS

```bash
VPS_HOST=user@YOUR_VPS_IP ./scripts/deploy_charlie_vps.sh
```

This builds the image locally, copies it to the VPS, and starts:

```text
yakr-relay serve --host 0.0.0.0 --port 8080 --role both --name charlie
```

Open **TCP 8090** on the VPS firewall (8080 is often taken by reverse proxies).

The script prints:

```bash
export CHARLIE_URL=http://YOUR_VPS_IP:8090
export CHARLIE_WRAP_SECRET=...   # optional; demo default if omitted
```

## 2. Run Alice + Bob locally

```bash
export CHARLIE_URL=http://YOUR_VPS_IP:8090
./scripts/demo_vps_charlie_relay.sh
```

The script will:

1. Check `CHARLIE_URL/healthz`
2. Init Alice (with Charlie operator contact) and Bob
3. Pair Alice ↔ Bob via Charlie rendezvous
4. Send messages both directions through Charlie
5. Show `profile show` — Alice lists `charlie` relay; Bob has none

## Dry-run without a VPS

Use the local `charlie-relay` service as a stand-in:

```bash
docker compose build charlie-relay
docker compose up -d charlie-relay
export CHARLIE_URL=http://host.docker.internal:8082
./scripts/demo_vps_charlie_relay.sh
```

(`host.docker.internal` is for containers; the script health-checks `127.0.0.1:8082` on your Mac.)

## Manual interactive steps

After setup:

```bash
export CHARLIE_URL=http://YOUR_VPS_IP:8090
COMPOSE="docker compose -f docker-compose.vps-charlie.yml"

$COMPOSE run --rm setup-vps-charlie
$COMPOSE run --rm --no-deps alice invite create --rendezvous "$CHARLIE_URL" --no-wait
$COMPOSE run --rm --no-deps alice invite relay wait    # terminal 1
$COMPOSE run --rm --no-deps bob invite accept "<invite-url>" --name alice  # terminal 2

$COMPOSE run --rm --no-deps alice send bob "hello"
$COMPOSE run --rm --no-deps bob fetch alice
```

## Notes

- Containers reach the VPS via its **public IP** in `CHARLIE_URL`.
- Bob never advertises Charlie; he uses Alice's profile + group relay fetch.
- For HTTPS, put Caddy/nginx in front of the relay and set `CHARLIE_URL=https://relay.example.com`.
