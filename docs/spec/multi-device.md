# Multi-Device Identity

**Status:** Spec / future work (not implemented in reference clients)

## The Question

Alice has Yakr on her phone and her laptop. How are both clients linked to one identity (Alice) without server accounts or passwords?

## What Exists Today

Each Yakr install is a **separate identity**:

```text
~/alice-phone/YAKR_HOME   → Identity keypair A₁ (Ed25519 + X25519)
~/alice-laptop/YAKR_HOME  → Identity keypair A₂ (different keys)
```

- There is **no central account server**. Your identity is the **local signing keypair** generated at first run (`yakr identity init`).
- Contacts pair with a **public bundle** (signing key, agreement key, optional PQ material) exchanged via invite URL or QR.
- `device_id` in inner messages is the first 16 hex chars of the **device signing public key** — it identifies which key produced the message, not a server-side user id.

So today, phone-Alice and laptop-Alice are **two different people** to the protocol unless you manually copy the same `YAKR_HOME` key material to both devices (not recommended: no sync, key theft on either device compromises the identity).

Bob who paired with phone-Alice has `contact.signing_public = A₁`. Messages signed by laptop-Alice (`A₂`) would **not** verify as Bob's contact Alice.

## Whitepaper Intent (§7.2, §26.6)

One **logical user identity** may authorize multiple **device keys**:

```text
Alice identity (signing root)
  ├── Alice iPhone   (device key D₁)
  ├── Alice MacBook  (device key D₂)
  └── Alice home relay (optional)
```

Device linking must be **explicit and visible** — no silent cloud backup of keys.

Planned approaches:

1. **Primary authorizes secondary** — primary device signs an enrollment record; secondary gets its own agreement keys but remains under Alice's identity root.
2. **Delivery profile lists device mailboxes** — Bob's client learns multiple mailbox descriptors for Alice's devices (or a fan-out policy).
3. **Encrypted local history transfer** — new device receives past messages from an existing device out-of-band, not from a server vault.
4. **Independent devices** — treat each device as a separate recipient (simplest; poor UX).

## Why No Passwords?

Yakr deliberately avoids server-authenticated accounts:

| Traditional | Yakr |
|-------------|------|
| Server stores user record + password hash | No user database on relay |
| Login proves account ownership | Pairwise invite proves contact relationship |
| Server can reset password | Only key holder can act as identity |

Trust anchors are **cryptographic keys** and **social pairing**, not operator credentials. Relays see opaque blobs and mailbox tags only.

## Implications for current features

### Ephemeral relay + local store

Relay blobs and local SQLite rows expire after **24 hours**. Delivery receipts confirm fetch so senders can clear `outbound_pending` without relay consume.

### Delivery profiles

A profile is signed by the contact's **identity signing key**. A multi-device design would extend the profile schema with per-device mailbox entries while keeping one identity signature root.

### Pairing

Bob pairs once with **Alice's identity root**, not per device. Secondary enrollment would be Alice-only (phone approves laptop) and optionally notifies Bob via a profile version bump.

## Recommended Next Step (Implementation)

Phase 9+ stretch:

1. **Identity root vs device keys** — split `Identity` into long-lived root + rotatable device subkeys.
2. **`device link` ceremony** — QR/NFC between Alice's devices; primary signs `DeviceEnrollment` CBOR.
3. **Profile v2** — `devices: [{device_id, agreement_public, mailbox_hint}]` signed by identity root.
4. **Client sync** — optional encrypted P2P or user-operated relay channel for history transfer (not cloud backup).

Until then, treat **one `YAKR_HOME` = one device = one identity** in tests and demos.
