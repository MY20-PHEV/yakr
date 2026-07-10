# Homelab Relay Runbook

**Audience:** Someone in a Yakr cell who wants **always-on mailboxes** for friends — without opening **443** on a home router or running a central platform.

**Remember:** A relay is an **operator role**, not a second chat device. Your phone stays the messaging identity; the homelab/VPS only stores opaque blobs.

## Choose your path

```text
                    ┌─────────────────────────────────────┐
                    │ Need friends OFF your home network   │
                    │ to reach this relay?               │
                    └─────────────────┬───────────────────┘
                                      │
                     NO              │              YES
                      │              │               │
                      ▼              │               ▼
            ┌─────────────────┐      │     ┌─────────────────────┐
            │ B. Tailscale /  │      │     │ Public reachability │
            │    WireGuard    │      │     └──────────┬──────────┘
            │  (no port fwd)  │      │                │
            └─────────────────┘      │       ┌────────┴────────┐
                                     │       │                   │
                                     │   At home?            Cloud VPS?
                                     │       │                   │
                                     │       ▼                   ▼
                                     │  ┌────────────┐    ┌──────────────┐
                                     │  │ A. Home    │    │ C. €5 VPS    │
                                     │  │ high port  │    │ (8090/443)   │
                                     │  │ e.g. 8090  │    │              │
                                     │  └────────────┘    └──────────────┘
```

| Path | Router | Typical URL | Best for |
|------|--------|-------------|----------|
| **A. Home high port** | Forward **one** TCP port (default **8090**) → relay host | `https://dyn-dns.example:8090` | Pi/NAS at home; small friend group |
| **B. Tailscale** | **No inbound ports** | `https://100.x.x.x:8090` or MagicDNS | Closed team; don't expose home IP |
| **C. VPS** | N/A (cloud firewall) | `https://vps-ip:8090` | Reliable uptime; friends not on your tailnet |

**Default relay process port inside the container/binary is 8080.** Homelab convention maps **host 8090 → container 8080** (see `scripts/deploy_charlie_vps.sh`).

Do **not** forward 443 at home unless you already run a reverse proxy there and want Yakr behind it — **8090 alone is enough** for the social-relay model (URL lives in signed profiles, not public discovery).

## Prerequisites (all paths)

1. **Messaging identity** — `yakr identity init --name alice` in your phone/laptop `YAKR_HOME`.
2. **Dedicated relay operator** (recommended for VPS/homelab) — one command:

   ```bash
   yakr relay create alice-ops --public-url https://relay.example:8090 --port 8090
   ```

   This creates `relays/alice-ops/` under your home, mints a **separate operator identity**, pre-pairs it with `alice`, writes TLS + `deploy/docker-compose.yml`, and adds an `alice-ops` contact so `yakr profile publish` may advertise the relay.

3. **Deploy** (VPS):

   ```bash
   yakr relay deploy alice-ops --vps user@203.0.113.10
   ```

   Wraps `scripts/deploy_charlie_vps.sh` with bundle TLS, wrap secret, and port from the manifest.

4. **Check**:

   ```bash
   yakr relay status alice-ops
   ```

### Manual operator setup (alternative)

If you prefer separate homes by hand:

1. `yakr identity init` in a dedicated `YAKR_HOME` for the relay operator.
2. **TLS** — pairing-anchored cert so peers pin SPKI in profiles ([tls-endpoints.md](spec/tls-endpoints.md)):

   ```bash
   uv run python scripts/generate_operator_relay_tls.py ~/.yakr/charlie-operator
   ```

3. **`yakr-relay`** — Docker image from repo root, or `uv run yakr-relay serve` on the host.

## Path A — Home router, port 8090

### 1. Run the relay

**From create bundle (homelab / local Docker):**

```bash
cd ~/.yakr/alice/relays/alice-ops/deploy
docker build -t yakr-relay:local /path/to/yakr/repo
docker compose up -d
```

**Or manual Docker:**

```bash
docker build -t yakr-relay:local .
docker run -d --name yakr-charlie --restart unless-stopped \
  -p 8090:8080 \
  -v yakr-charlie-data:/data \
  -v "$HOME/.yakr/charlie-operator/relay-tls:/tls:ro" \
  yakr-relay:local \
  yakr-relay serve --host 0.0.0.0 --port 8080 --data-dir /data \
    --role both --name charlie \
    --wrap-secret "$CHARLIE_WRAP_SECRET" \
    --ssl-keyfile /tls/endpoint.key.pem \
    --ssl-certfile /tls/endpoint.cert.pem
```

**Native:**

```bash
uv run yakr-relay serve --host 0.0.0.0 --port 8090 \
  --data-dir /var/lib/yakr-relay \
  --role both --name charlie \
  --wrap-secret "$CHARLIE_WRAP_SECRET" \
  --ssl-keyfile ... --ssl-certfile ...
```

### 2. Router / firewall

- Forward **TCP 8090** → relay machine (not 443).
- Allow outbound from relay host (for sweeper / optional forward).
- Optional: restrict source IPs if your cell is fixed (most cells use profile + TLS pin instead).

### 3. Dynamic IP

- Use DDNS or a stable hostname in the profile.
- After IP changes: `yakr presence push` so peers learn the new URL before profile TTL expires ([presence-minimal.md](spec/presence-minimal.md)).

### 4. Publish to contacts

```bash
export YAKR_RELAY_URL=https://your-hostname:8090
export YAKR_RELAY_NAME=charlie   # must match operator identity name
yakr profile publish
yakr profile push alice          # each contact; wait for receipt / their fetch
```

Peers learn **URL + TLS pin** from your signed profile. They only need **outbound** HTTPS to `:8090`.

### 5. Hardening (internet-facing)

```bash
# optional on relay container:
yakr-relay serve ... --require-tickets
```

Plus reverse-proxy rate limits if exposed to the open internet.

## Path B — Tailscale (no port forward)

1. Install Tailscale on relay host (and on peers **or** use Tailscale Funnel only if you accept wider exposure).
2. Run relay bound to tailnet IP or `0.0.0.0:8090` (tailnet only reaches it).
3. Profile URL: `https://<magicdns>:8090` or `https://100.x.x.x:8090`.
4. Same `profile publish` / `profile push` flow.

**Limitation:** Peers not on your tailnet cannot poll unless you also run Path A/C or share a group VPS.

## Path C — Small VPS (€5/month class)

Same as homelab deploy script:

```bash
uv run python scripts/generate_operator_relay_tls.py ~/.yakr/charlie-operator
export VPS_HOST=user@203.0.113.10
export CHARLIE_TLS_DIR=$HOME/.yakr/charlie-operator/relay-tls
./scripts/deploy_charlie_vps.sh
```

Open **TCP 8090** (or 443 behind nginx) on the **cloud** firewall — not your home router.

See [demo-vps-charlie.md](demo-vps-charlie.md) for Alice/Bob + remote Charlie workflow.

## Checklist after deploy

| Step | Command / check |
|------|------------------|
| Health | `curl -k https://HOST:8090/healthz` |
| Profile lists relay | `yakr profile show` → `relay_descriptors` |
| Contacts updated | `yakr profile push <contact>` for each peer |
| Peer can send | Contact sends test message; check relay logs / blob store |
| Peer can receive | `yakr fetch <you>` on peer; delivery receipt clears pending |
| IP change | `yakr presence push` |

## Relay-less peers (Bob)

Not everyone in the cell runs a relay.

- **Bob** pairs with **Alice** and **Charlie (operator)**.
- Bob **does not** need his own relay or home port forward.
- Bob **sends** using Alice's profile relays; **receives** on his mailboxes (if any) or Alice's sender fallbacks (Charlie).
- Bob runs `yakr fetch alice` — polls **only Alice's relays + his own** (not every relay in the graph).

See [relay-authorization.md](spec/relay-authorization.md).

## Related docs

- [relay-authorization.md](spec/relay-authorization.md) — advertise vs use
- [relay-failover.md](spec/relay-failover.md) — ordered mailbox POST
- [fetch-algorithm.md](spec/fetch-algorithm.md) — per-contact fetch (default) vs `--wide`
- CLI: `yakr relay create` / `deploy` / `status` — operator bundle under `relays/<name>/`
- [demo-vps-charlie.md](demo-vps-charlie.md) — VPS Charlie demo
- [ADR 008](adr/008-nat-reachability-and-mobile-delivery.md) — why phones poll outbound
