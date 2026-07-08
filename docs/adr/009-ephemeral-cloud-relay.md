# ADR 009: Ephemeral Cloud Relay Deploy (Future)

**Status:** Proposed (not implemented)  
**Date:** 2026-07-08

## Context

Typical Yakr users are on mobile and cannot run an inbound-reachable mailbox on cellular or iOS (see ADR 008). Message delivery depends on **reachable relays** operated by paired contacts — often a friend's homelab VPS (Charlie/Dennis in demos).

The reference relay is already **containerized** (`yakr-relay` Docker image) with homelab deploy scripts (`deploy_charlie_vps.sh`, `generate_operator_relay_tls.py`). Operators today need SSH and manual env vars.

Many users could run **their own** relay in **their own** cloud account (AWS, GCP, etc.) if provisioning, pairing, TLS, and profile update were automated — and tear down just as easily when done.

This is **self-operated relay** (relay-authorization rule 1), not a Yakr-platform-hosted relay. It extends the social-relay model without centralising infrastructure.

## Proposal

Provide a client or CLI flow:

```text
yakr relay deploy --provider aws --region eu-west-1
yakr relay status
yakr relay destroy
```

Or equivalent mobile wizard: OAuth to cloud provider → deploy stack → callback with public URL.

### Provisioned stack (per provider module)

- Small compute (e.g. EC2 t4g.nano, Cloud Run, Fly.io, GCE e2-micro)
- Security group / firewall: TCP 443 or 8090 from internet
- `yakr-relay` container with:
  - `--role both`
  - pairing-anchored TLS PEM (from operator identity)
  - persistent volume for blob store (optional; 24h TTL limits need anyway)
- Public URL (IP or optional DNS)

### Pairing baked in

At deploy time the tool SHOULD:

1. Use or create a **relay operator identity** (`YAKR_HOME` for relay operator, distinct from daily messaging identity or sub-key — TBD).
2. Run `generate_operator_relay_tls.py` equivalent → SPKI pin.
3. Build `relay_descriptor_for_operator()` and merge into the user's **signed delivery profile**.
4. `profile publish` / `presence push` with the new public URL.
5. Store cloud resource IDs locally for `destroy`.

On **destroy**:

1. Tear down cloud resources (Terraform/Pulumi/CloudFormation destroy or provider API).
2. Remove or mark stale the relay descriptor in profile; publish updated profile.
3. Warn that undelivered blobs on that relay may be lost (within existing TTL semantics).

### Trust model (unchanged)

- Peers use the relay because **your signed profile** lists it with your operator `name`, `wrap_secret`, and `tls_spki_sha256`.
- No new “pair with AWS” contact — you remain the operator contact.
- Friends who already paired with you learn the new URL via profile/presence; transitive TLS pin rules unchanged.

## Why containerized deploy fits

| Existing piece | Cloud deploy reuses |
|----------------|---------------------|
| `Dockerfile` / relay image | Same image on ECS/Fargate/Compute Engine |
| `deploy_charlie_vps.sh` | Pattern for TLS upload + `docker run` |
| `relay_descriptor_for_operator()` | Auto-published descriptor |
| Pairing-anchored TLS | Same SPKI pin model |
| ADR 008 relay-first mobile | User gets reachable mailbox without homelab |

## Open design questions

| Topic | Options |
|-------|---------|
| Operator identity | Dedicated relay sub-identity vs main user identity |
| Key custody | Keys on VM vs KMS/sealed enclave |
| Cost controls | Smallest SKU, auto-destroy after idle, billing alerts |
| Provider order | AWS first (CloudFormation/Terraform), then GCP |
| DNS | Raw IP + presence vs Route53/Cloudflare optional |
| Multi-relay | User runs AWS + friend runs homelab as failover list |

## Non-goals

- Yakr-operated multi-tenant relay SaaS (central platform)
- Replacing friend homelab relays — complementary
- Wire-level P2P — still store-and-forward mailbox

## Consequences (if built)

**Positive**

- Mobile-first users can be their own operator without SSH/homelab
- Ephemeral trials (“spin up for a trip, destroy after”)
- Strengthens decentralisation story: **your** cloud account, **your** container

**Negative**

- IaC maintenance per cloud provider
- User cloud billing and security (leaked AWS keys)
- App Store / Play review if one-click deploy from mobile

## References

- ADR 008 — NAT, mobile, relay-first delivery
- `docs/spec/relay-authorization.md` — self-operated relay rule
- `scripts/deploy_charlie_vps.sh`, `scripts/generate_operator_relay_tls.py`
- `docs/demo-vps-charlie.md`
