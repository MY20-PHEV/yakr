"""Independent v1.0 interop verifier — no yakr_core imports."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from yakr_testkit.hybrid_verify import verify_hybrid_master

MAILBOX_TAG_INFO = b"yakr/v0.1/mailbox-tag"


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _hkdf_derive(ikm: bytes, info: bytes, *, salt: bytes = b"", length: int = 32) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)


def _invite_unsigned(payload: dict[str, object]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key not in ("signature", "pq_signature")}
    return cbor2.dumps(unsigned)


def _profile_unsigned(payload: dict[str, object]) -> bytes:
    return cbor2.dumps(
        {
            "protocol": payload["protocol"],
            "version": payload["version"],
            "valid_from": payload["valid_from"],
            "valid_until": payload["valid_until"],
            "direct_hints": payload["direct_hints"],
            "relay_descriptors": payload["relay_descriptors"],
            "mailbox_params": payload["mailbox_params"],
            "blob_classes": payload["blob_classes"],
            "receipt_policy": payload["receipt_policy"],
        }
    )


def verify_hybrid_kex_vector(vector: dict[str, object]) -> bool:
    identity_shared = bytes.fromhex(str(vector["identity_shared_hex"]))
    ephemeral_shared = bytes.fromhex(str(vector["ephemeral_shared_hex"]))
    pq_secret = bytes.fromhex(str(vector["pq_secret_hex"]))
    transcript_hash = bytes.fromhex(str(vector["transcript_hash_hex"]))
    expected = bytes.fromhex(str(vector["expected_master_hex"]))
    return verify_hybrid_master(
        identity_shared=identity_shared,
        ephemeral_shared=ephemeral_shared,
        pq_secret=pq_secret,
        transcript_hash=transcript_hash,
        expected_master=expected,
    )


def verify_mailbox_tag_vector(vector: dict[str, object]) -> bool:
    master_secret = bytes.fromhex(str(vector["master_secret_hex"]))
    direction = str(vector["direction"])
    epoch = int(vector["epoch"])
    expected = bytes.fromhex(str(vector["expected_tag_hex"]))

    mailbox_secret = _hkdf_derive(master_secret, MAILBOX_TAG_INFO + direction.encode("utf-8"))
    material = f"{direction}|{epoch}".encode("utf-8")
    tag = hmac.new(mailbox_secret, material, hashlib.sha256).digest()
    return tag == expected


def verify_invite_vector(vector: dict[str, object]) -> bool:
    bundle = cbor2.loads(_b64decode(str(vector["bundle_b64"])))
    signing_public = bytes(bundle["signing_public"])
    if signing_public.hex() != str(vector["signing_public_hex"]):
        return False

    public_key = ed25519.Ed25519PublicKey.from_public_bytes(signing_public)
    try:
        public_key.verify(bytes(bundle["signature"]), _invite_unsigned(bundle))
    except Exception:
        return False

    digest = hashlib.sha256(signing_public + bytes(bundle["agreement_public"])).digest()
    digits = "".join(str(byte % 10) for byte in digest[:10])
    safety = f"{digits[0:4]} {digits[4:8]} {digits[8:10]}"
    return safety == str(vector["safety_code"])


def verify_delivery_profile_vector(vector: dict[str, object]) -> bool:
    payload = cbor2.loads(_b64decode(str(vector["profile_b64"])))
    signing_public = bytes.fromhex(str(vector["signing_public_hex"]))
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(signing_public)
    try:
        public_key.verify(bytes(payload["signature"]), _profile_unsigned(payload))
    except Exception:
        return False
    return int(payload["version"]) == int(vector["version"])


def verify_inner_message_vector(vector: dict[str, object]) -> bool:
    raw = str(vector["json"]).encode("utf-8")
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("conversation_id") != vector["conversation_id"]:
        return False
    if int(payload.get("seq", -1)) != int(vector["seq"]):
        return False
    if payload.get("body") != vector["body"]:
        return False
    # Canonical re-encode must match fixed vector bytes.
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return canonical == raw


def verify_all_vectors(vectors_dir: str | Path) -> None:
    root = Path(vectors_dir)
    checks = [
        ("hybrid_kex.json", verify_hybrid_kex_vector, True),
        ("mailbox_tag.json", verify_mailbox_tag_vector, False),
        ("invite.json", verify_invite_vector, False),
        ("delivery_profile.json", verify_delivery_profile_vector, False),
        ("inner_message.json", verify_inner_message_vector, False),
    ]
    for filename, verifier, is_array in checks:
        data = json.loads((root / filename).read_text(encoding="utf-8"))
        items = data if is_array else [data]
        for item in items:
            if not verifier(item):
                raise AssertionError(f"vector failed: {filename} ({item.get('name', 'unnamed')})")
