# VPS Charlie demo (Alice + Bob local, Charlie on VPS)

Alice and Bob run in **local Docker containers**. Charlie is a `yakr-relay` on your VPS (pairing rendezvous + message store).

Alice is pre-paired with the Charlie relay operator. Bob is not.

All production paths use **HTTPS** with **pairing-anchored TLS** (SPKI pins in signed profiles). Plain HTTP is dev-only (`YAKR_REQUIRE_TLS=0`).

## 1. Deploy Charlie on your VPS

### HTTP (dev / quick smoke test)

```bash
VPS_HOST=user@YOUR_VPS_IP ./scripts/deploy_charlie_vps.sh
```

### HTTPS (recommended homelab / production)

Generate TLS from the Charlie **operator identity** (same key material pinned in profiles):

```bash
# One-time: create operator identity locally (or reuse charlie-operator-data volume)
mkdir -p /tmp/charlie-operator
YAKR_HOME=/tmp/charlie-operator yakr init --name charlie --force
python scripts/generate_operator_relay_tls.py /tmp/charlie-operator

VPS_HOST=user@YOUR_VPS_IP \
  CHARLIE_TLS_DIR=/tmp/charlie-operator/relay-tls \
  ./scripts/deploy_charlie_vps.sh
```

Open **TCP 8090** on the VPS firewall.

Export:

```bash
export CHARLIE_URL=https://YOUR_VPS_IP:8090
export CHARLIE_WRAP_SECRET=...   # printed by deploy script
```

The operator profile created during setup embeds `tls_spki_sha256` on each relay descriptor — clients verify Charlie's cert without a public CA.

## 2. Run Alice + Bob locally

```bash
export CHARLIE_URL=https://YOUR_VPS_IP:8090
export YAKR_REQUIRE_TLS=1
./scripts/demo_vps_charlie_relay.sh
```

The script will:

1. Check `CHARLIE_URL/healthz` (TLS pin from Alice's Charlie contact)
2. Init Alice (with Charlie operator contact) and Bob
3. Pair Alice ↔ Bob via Charlie rendezvous
4. Send messages both directions through Charlie
5. Show `profile show` — Alice lists `charlie` relay with TLS pin; Bob uses Alice's profile

## 3. Operator workflow: IP or host change

Signed profile URLs can lag. Use **presence** for live location:

```bash
# On Charlie operator (after relay URL changes):
export YAKR_RELAY_URL=https://NEW_HOST:8090
export YAKR_RELAY_NAME=charlie
yakr profile publish              # fan-out presence when URL changes
# or immediately:
yakr presence push

# On each peer (Alice, Bob):
yakr fetch alice    # or fetch each contact — learns new presence on poll
```

Recovery after outage:

```bash
yakr fetch <contact>              # drain messages + send receipts
yakr receipts flush               # retry receipts queued during outage
yakr resend <contact>             # resend outbound pending
```

## Dry-run without a VPS

Use the local `charlie-relay` service as a stand-in (HTTP dev mode):

```bash
docker compose build charlie-relay
docker compose up -d charlie-relay
export CHARLIE_URL=http://host.docker.internal:8082
export YAKR_REQUIRE_TLS=0
./scripts/demo_vps_charlie_relay.sh
```

## Manual interactive steps

After setup:

```bash
export CHARLIE_URL=https://YOUR_VPS_IP:8090
export YAKR_REQUIRE_TLS=1
COMPOSE="docker compose -f docker-compose.vps-charlie.yml"

$COMPOSE run --rm setup-vps-charlie
$COMPOSE run --rm --no-deps alice invite create --rendezvous "$CHARLIE_URL" --no-wait
$COMPOSE run --rm --no-deps alice invite relay wait    # terminal 1
$COMPOSE run --rm --no-deps bob invite accept "<invite-url>" --name alice  # terminal 2

$COMPOSE run --rm --no-deps alice send bob "hello"
$COMPOSE run --rm --no-deps bob fetch alice
$COMPOSE run --rm --no-deps bob receipts pending      # if relay was down during fetch
$COMPOSE run --rm --no-deps bob receipts flush
```

## Notes

- Containers reach the VPS via its **public IP** (or Tailscale IP) in `CHARLIE_URL`.
- Bob never advertises Charlie; he uses Alice's signed profile + relay descriptor TLS pins.
- Optional second relay: `DENNIS_URL=https://...` on setup (see `scripts/setup_vps_charlie_demo.py`).
- See [tls-endpoints.md](spec/tls-endpoints.md) and [presence-minimal.md](spec/presence-minimal.md).
