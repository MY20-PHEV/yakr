"""Independent v1.0 interop verifier — no yakr_core imports."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from nacl import bindings as nacl_bindings

from yakr_testkit.hybrid_verify import verify_hybrid_master

MAILBOX_TAG_INFO = b"yakr/v0.1/mailbox-tag"
PAIR_MASTER_INFO = b"yakr/v0.4/pair-master"
HYBRID_PQ_CAPABILITY = "hybrid_pq"

RATCHET_MAGIC = b"YKDR2"
MAX_SKIP_GAP = 128
MAX_SKIPPED_KEYS = 256
ROOT_INFO = b"yakr/v1.0/double-ratchet-root"
RK_INFO = b"yakr/v1.0/double-ratchet-rk"
CK_INFO = b"yakr/v1.0/double-ratchet-ck"
SEND_CHAIN_INFO = b"yakr/v1.0/double-ratchet-send"
RECV_CHAIN_INFO = b"yakr/v1.0/double-ratchet-recv"


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _hkdf_derive(ikm: bytes, info: bytes, *, salt: bytes = b"", length: int = 32) -> bytes:
    return HKDF(hashes.SHA256(), length, salt, info).derive(ikm)


def _hkdf64(ikm: bytes, info: bytes, *, salt: bytes = b"") -> tuple[bytes, bytes]:
    material = HKDF(hashes.SHA256(), 64, salt, info).derive(ikm)
    return material[:32], material[32:]


def _x25519_shared_secret(private_bytes: bytes, peer_public: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    return private_key.exchange(peer)


def _x25519_public_from_private(private_bytes: bytes) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _xchacha_encrypt(key: bytes, plaintext: bytes, *, associated_data: bytes = b"") -> bytes:
    import os

    nonce = os.urandom(24)
    ciphertext = nacl_bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext,
        associated_data,
        nonce,
        key,
    )
    return nonce + ciphertext


def _xchacha_decrypt(key: bytes, payload: bytes, *, associated_data: bytes = b"") -> bytes:
    if len(payload) < 24:
        raise ValueError("ciphertext too short")
    nonce, ciphertext = payload[:24], payload[24:]
    return nacl_bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        ciphertext,
        associated_data,
        nonce,
        key,
    )


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


def _pairing_transcript_hash(vector: dict[str, object]) -> bytes:
    parts = [
        str(vector.get("invite_protocol", "yakr-v0.4")).encode("utf-8"),
        bytes.fromhex(str(vector["invite_secret_hex"])),
        bytes.fromhex(str(vector["invite_signing_public_hex"])),
        bytes.fromhex(str(vector["invite_agreement_public_hex"])),
        bytes.fromhex(str(vector["joiner_signing_public_hex"])),
        bytes.fromhex(str(vector["joiner_agreement_public_hex"])),
        bytes.fromhex(str(vector["joiner_ephemeral_public_hex"])),
        bytes.fromhex(str(vector["inviter_ephemeral_public_hex"])),
        bytes.fromhex(str(vector["joiner_ratchet_public_hex"])),
        bytes.fromhex(str(vector["inviter_ratchet_public_hex"])),
    ]
    if vector.get("kem_ciphertext_hex"):
        parts.append(bytes.fromhex(str(vector["kem_ciphertext_hex"])))
    return hashlib.sha256(b"|".join(parts)).digest()


def _derive_classical_pair_master(
    identity_shared: bytes,
    ephemeral_shared: bytes,
    transcript_hash: bytes,
) -> bytes:
    return _hkdf_derive(identity_shared + ephemeral_shared, PAIR_MASTER_INFO, salt=transcript_hash)


def _kem_decapsulate_ml_kem_768(secret_key: bytes, ciphertext: bytes) -> bytes:
    from pqcrypto.kem.ml_kem_768 import decrypt

    return decrypt(secret_key, ciphertext)


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


def _message_id(ciphertext: bytes) -> str:
    return hashlib.sha256(b"yakr/v0.1/message-id|" + ciphertext).hexdigest()


def _outer_blob_from_relay_json(payload: dict[str, object]) -> tuple[int, bytes, int, bytes]:
    if "mailbox_tag" not in payload:
        raise ValueError("missing mailbox_tag")
    if "expires_at" not in payload:
        raise ValueError("missing expires_at")
    if "ciphertext" not in payload:
        raise ValueError("missing ciphertext")
    tag = _b64decode(str(payload["mailbox_tag"]))
    if len(tag) != 32:
        raise ValueError("mailbox_tag must be 32 bytes")
    ciphertext = _b64decode(str(payload["ciphertext"]))
    return 1, tag, int(payload["expires_at"]), ciphertext


def verify_inner_message_vector(vector: dict[str, object]) -> bool:
    raw = str(vector["json"]).encode("utf-8")
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("conversation_id") != vector["conversation_id"]:
        return False
    if int(payload.get("seq", -1)) != int(vector["seq"]):
        return False
    if payload.get("body") != vector["body"]:
        return False
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return canonical == raw


def verify_inner_receipt_vector(vector: dict[str, object]) -> bool:
    raw = str(vector["json"]).encode("utf-8")
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("conversation_id") != vector["conversation_id"]:
        return False
    if int(payload.get("seq", -1)) != int(vector["seq"]):
        return False
    if payload.get("type") != vector["type"]:
        return False
    if payload.get("message_id") != vector["message_id"]:
        return False
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if canonical != raw:
        return False
    ciphertext = bytes.fromhex(str(vector["referenced_ciphertext_hex"]))
    return _message_id(ciphertext) == str(vector["message_id"])


def verify_outer_blob_vector(vector: dict[str, object]) -> bool:
    relay = vector.get("relay_json")
    if not isinstance(relay, dict):
        return False
    try:
        version, tag, expires_at, ciphertext = _outer_blob_from_relay_json(relay)
    except Exception:
        return False
    if version != int(vector["version"]):
        return False
    if tag.hex() != str(vector["mailbox_tag_hex"]):
        return False
    if expires_at != int(vector["expires_at"]):
        return False
    return ciphertext.hex() == str(vector["ciphertext_hex"])


def verify_pairing_transcript_vector(vector: dict[str, object]) -> bool:
    transcript = _pairing_transcript_hash(vector)
    if transcript.hex() != str(vector["expected_transcript_hash_hex"]):
        return False

    inv_agree = bytes.fromhex(str(vector["inviter_agreement_private_hex"]))
    inv_eph = bytes.fromhex(str(vector["inviter_ephemeral_private_hex"]))
    join_agree_pub = bytes.fromhex(str(vector["joiner_agreement_public_hex"]))
    join_eph_pub = bytes.fromhex(str(vector["joiner_ephemeral_public_hex"]))

    identity_shared = _x25519_shared_secret(inv_agree, join_agree_pub)
    ephemeral_shared = _x25519_shared_secret(inv_eph, join_eph_pub)
    if identity_shared.hex() != str(vector["expected_identity_shared_hex"]):
        return False
    if ephemeral_shared.hex() != str(vector["expected_ephemeral_shared_hex"]):
        return False

    if vector.get("kem_ciphertext_hex"):
        pq_secret = _kem_decapsulate_ml_kem_768(
            bytes.fromhex(str(vector["inviter_kem_secret_hex"])),
            bytes.fromhex(str(vector["kem_ciphertext_hex"])),
        )
        if pq_secret.hex() != str(vector["expected_pq_secret_hex"]):
            return False
        expected_master = bytes.fromhex(str(vector["expected_master_secret_hex"]))
        if not verify_hybrid_master(
            identity_shared=identity_shared,
            ephemeral_shared=ephemeral_shared,
            pq_secret=pq_secret,
            transcript_hash=transcript,
            expected_master=expected_master,
        ):
            return False
        master = expected_master
    else:
        master = _derive_classical_pair_master(identity_shared, ephemeral_shared, transcript)
        if master.hex() != str(vector["expected_master_secret_hex"]):
            return False

    join_agree = bytes.fromhex(str(vector["joiner_agreement_private_hex"]))
    join_eph = bytes.fromhex(str(vector["joiner_ephemeral_private_hex"]))
    invite_agree_pub = bytes.fromhex(str(vector["invite_agreement_public_hex"]))
    inv_eph_pub = bytes.fromhex(str(vector["inviter_ephemeral_public_hex"]))

    joiner_identity = _x25519_shared_secret(join_agree, invite_agree_pub)
    joiner_ephemeral = _x25519_shared_secret(join_eph, inv_eph_pub)
    if vector.get("kem_ciphertext_hex"):
        joiner_master = HKDF(hashes.SHA256(), 32, transcript, b"yakr/v0.6/hybrid-master").derive(
            joiner_identity + joiner_ephemeral + pq_secret
        )
    else:
        joiner_master = _derive_classical_pair_master(joiner_identity, joiner_ephemeral, transcript)
    return master == joiner_master


def verify_double_ratchet_vector(vector: dict[str, object]) -> bool:
    master = bytes.fromhex(str(vector["master_secret_hex"]))
    root = _hkdf_derive(master, ROOT_INFO)
    if root.hex() != str(vector["alice_root_key_hex"]):
        return False
    if _hkdf_derive(root, SEND_CHAIN_INFO).hex() != str(vector["alice_send_chain_hex"]):
        return False
    if _hkdf_derive(root, RECV_CHAIN_INFO).hex() != str(vector["alice_recv_chain_hex"]):
        return False

    alice_private = bytes.fromhex(str(vector["alice_dh_self_private_hex"]))
    bob_private = bytes.fromhex(str(vector["bob_dh_self_private_hex"]))
    alice_public = _x25519_public_from_private(alice_private)
    bob_public = _x25519_public_from_private(bob_private)
    if alice_public.hex() != str(vector["alice_dh_self_public_hex"]):
        return False
    if bob_public.hex() != str(vector["bob_dh_self_public_hex"]):
        return False

    alice_send = _hkdf_derive(root, SEND_CHAIN_INFO)
    alice_recv = _hkdf_derive(root, RECV_CHAIN_INFO)
    bob_send = _hkdf_derive(root, RECV_CHAIN_INFO)
    bob_recv = _hkdf_derive(root, SEND_CHAIN_INFO)

    plaintext = bytes.fromhex(str(vector["plaintext_hex"]))
    send_n = 0
    prev_send_n = 0
    message_key, alice_send = _hkdf64(alice_send, CK_INFO, salt=b"")
    aad = RATCHET_MAGIC + alice_public + struct.pack(">II", prev_send_n, send_n)
    ciphertext = RATCHET_MAGIC + alice_public + struct.pack(">II", prev_send_n, send_n)
    ciphertext += _xchacha_encrypt(message_key, plaintext, associated_data=aad)

    if ciphertext[: len(RATCHET_MAGIC)] != RATCHET_MAGIC:
        return False
    if ciphertext[len(RATCHET_MAGIC) : len(RATCHET_MAGIC) + 32].hex() != str(vector["header_dh_public_hex"]):
        return False
    header_end = len(RATCHET_MAGIC) + 32 + 8
    prev_n, message_n = struct.unpack(">II", ciphertext[len(RATCHET_MAGIC) + 32 : header_end])
    if prev_n != int(vector["header_prev_n"]):
        return False
    if message_n != int(vector["header_message_n"]):
        return False

    peer_public = ciphertext[5:37]
    payload_ct = ciphertext[45:]
    recv_n = 0
    message_key, bob_recv = _hkdf64(bob_recv, CK_INFO, salt=b"")
    if message_n != recv_n:
        return False
    recv_n = message_n + 1
    aad = RATCHET_MAGIC + peer_public + struct.pack(">II", prev_n, message_n)
    try:
        decrypted = _xchacha_decrypt(message_key, payload_ct, associated_data=aad)
    except Exception:
        return False
    return decrypted == plaintext


def _kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    return _hkdf64(root_key, RK_INFO, salt=dh_output)


def _invite_supports_hybrid(*, protocol: str, kem_public_hex: str) -> bool:
    return protocol == "yakr-v0.6" and bool(kem_public_hex)


def _validate_pairing_request_for_invite(vector: dict[str, object]) -> None:
    invite_secret = bytes.fromhex(str(vector["invite_secret_hex"]))
    request_secret = bytes.fromhex(str(vector["request_invite_secret_hex"]))
    joiner_ratchet = bytes.fromhex(str(vector["joiner_ratchet_public_hex"]))
    kem_ciphertext = bytes.fromhex(str(vector.get("kem_ciphertext_hex") or ""))
    if request_secret != invite_secret:
        raise ValueError("pairing invite secret mismatch")
    if len(joiner_ratchet) != 32:
        raise ValueError("pairing request missing joiner ratchet public key")
    if _invite_supports_hybrid(
        protocol=str(vector["invite_protocol"]),
        kem_public_hex=str(vector.get("invite_kem_public_hex") or ""),
    ):
        if not kem_ciphertext:
            raise ValueError("hybrid invite requires kem ciphertext")
        return
    if kem_ciphertext:
        raise ValueError("unexpected kem ciphertext on classical invite")


def _pairing_request_from_bytes(data: bytes) -> dict[str, object]:
    payload = cbor2.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("invalid pairing request")
    return payload


def _pairing_response_from_bytes(data: bytes) -> dict[str, object]:
    payload = cbor2.loads(data)
    if not isinstance(payload, dict):
        raise ValueError("invalid pairing response")
    return payload


class _RatchetSession:
    """Minimal double-ratchet receiver/sender for negative vector checks."""

    def __init__(
        self,
        *,
        root_key: bytes,
        dh_self_private: bytes,
        dh_self_public: bytes,
        send_chain_key: bytes,
        recv_chain_key: bytes,
    ) -> None:
        self.root_key = root_key
        self.dh_self_private = dh_self_private
        self.dh_self_public = dh_self_public
        self.dh_peer_public: bytes | None = None
        self.send_chain_key = send_chain_key
        self.recv_chain_key = recv_chain_key
        self.send_n = 0
        self.recv_n = 0
        self.prev_send_n = 0
        self.skipped_keys: dict[str, bytes] = {}

    @classmethod
    def from_bootstrap_vector(cls, vector: dict[str, object], *, side: str) -> tuple[_RatchetSession, _RatchetSession]:
        master = bytes.fromhex(str(vector["master_secret_hex"]))
        root = _hkdf_derive(master, ROOT_INFO)
        send_chain = _hkdf_derive(root, SEND_CHAIN_INFO)
        recv_chain = _hkdf_derive(root, RECV_CHAIN_INFO)
        alice_private = bytes.fromhex(str(vector["alice_dh_self_private_hex"]))
        bob_private = bytes.fromhex(str(vector["bob_dh_self_private_hex"]))
        alice_public = _x25519_public_from_private(alice_private)
        bob_public = _x25519_public_from_private(bob_private)
        alice = cls(
            root_key=root,
            dh_self_private=alice_private,
            dh_self_public=alice_public,
            send_chain_key=send_chain,
            recv_chain_key=recv_chain,
        )
        bob = cls(
            root_key=root,
            dh_self_private=bob_private,
            dh_self_public=bob_public,
            send_chain_key=recv_chain,
            recv_chain_key=send_chain,
        )
        if side == "alice":
            return alice, bob
        return bob, alice

    def _skip_key(self, peer_public: bytes, message_n: int) -> bytes:
        return self.skipped_keys[f"{peer_public.hex()}:{message_n}"]

    def _store_skip(self, peer_public: bytes, message_n: int, message_key: bytes) -> None:
        self.skipped_keys[f"{peer_public.hex()}:{message_n}"] = message_key

    def _dh_ratchet(self, peer_public: bytes) -> None:
        private_key = x25519.X25519PrivateKey.generate()
        self.dh_self_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.dh_self_public = _x25519_public_from_private(self.dh_self_private)
        dh_output = _x25519_shared_secret(self.dh_self_private, peer_public)
        self.root_key, self.send_chain_key = _kdf_rk(self.root_key, dh_output)
        self.prev_send_n = self.send_n
        self.send_n = 0
        self.dh_peer_public = peer_public

    def _snapshot(self) -> dict[str, object]:
        return {
            "root_key": self.root_key,
            "dh_self_private": self.dh_self_private,
            "dh_self_public": self.dh_self_public,
            "dh_peer_public": self.dh_peer_public,
            "send_chain_key": self.send_chain_key,
            "recv_chain_key": self.recv_chain_key,
            "send_n": self.send_n,
            "recv_n": self.recv_n,
            "prev_send_n": self.prev_send_n,
            "skipped_keys": dict(self.skipped_keys),
        }

    def _restore(self, snapshot: dict[str, object]) -> None:
        self.root_key = bytes(snapshot["root_key"])
        self.dh_self_private = bytes(snapshot["dh_self_private"])
        self.dh_self_public = bytes(snapshot["dh_self_public"])
        self.dh_peer_public = snapshot["dh_peer_public"]
        self.send_chain_key = snapshot["send_chain_key"]
        self.recv_chain_key = snapshot["recv_chain_key"]
        self.send_n = int(snapshot["send_n"])
        self.recv_n = int(snapshot["recv_n"])
        self.prev_send_n = int(snapshot["prev_send_n"])
        self.skipped_keys = dict(snapshot["skipped_keys"])

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.send_chain_key is None:
            raise ValueError("send chain not initialized")
        message_key, self.send_chain_key = _hkdf64(self.send_chain_key, CK_INFO, salt=b"")
        aad = RATCHET_MAGIC + self.dh_self_public + struct.pack(">II", self.prev_send_n, self.send_n)
        ciphertext = _xchacha_encrypt(message_key, plaintext, associated_data=aad)
        header = RATCHET_MAGIC + self.dh_self_public + struct.pack(">II", self.prev_send_n, self.send_n)
        self.send_n += 1
        return header + ciphertext

    def decrypt(self, payload: bytes) -> bytes:
        if len(payload) < len(RATCHET_MAGIC) + 32 + 8:
            raise ValueError("ratchet payload too short")
        if not payload.startswith(RATCHET_MAGIC):
            raise ValueError("invalid ratchet header")
        offset = len(RATCHET_MAGIC)
        peer_public = payload[offset : offset + 32]
        offset += 32
        prev_n, message_n = struct.unpack(">II", payload[offset : offset + 8])
        offset += 8
        ciphertext = payload[offset:]

        snapshot = self._snapshot()
        try:
            if self.dh_peer_public is None:
                self.dh_peer_public = peer_public
            elif self.dh_peer_public != peer_public:
                self._dh_ratchet(peer_public)

            if self.recv_chain_key is None:
                raise ValueError("recv chain not initialized")

            if message_n < self.recv_n:
                try:
                    message_key = self._skip_key(peer_public, message_n)
                except KeyError:
                    raise ValueError("ratchet message already received") from None
            else:
                gap = message_n - self.recv_n
                if gap > MAX_SKIP_GAP:
                    raise ValueError("ratchet skip gap too large")
                if len(self.skipped_keys) + gap > MAX_SKIPPED_KEYS:
                    raise ValueError("ratchet skipped key limit exceeded")
                while self.recv_n < message_n:
                    mk, self.recv_chain_key = _hkdf64(self.recv_chain_key, CK_INFO, salt=b"")
                    self._store_skip(peer_public, self.recv_n, mk)
                    self.recv_n += 1
                message_key, self.recv_chain_key = _hkdf64(self.recv_chain_key, CK_INFO, salt=b"")
                self.recv_n = message_n + 1

            aad = RATCHET_MAGIC + peer_public + struct.pack(">II", prev_n, message_n)
            return _xchacha_decrypt(message_key, ciphertext, associated_data=aad)
        except Exception:
            self._restore(snapshot)
            raise


def _load_bootstrap_vector(vectors_dir: Path, name: str) -> dict[str, object]:
    vectors = json.loads((vectors_dir / "double_ratchet.json").read_text(encoding="utf-8"))
    for vector in vectors:
        if vector.get("name") == name:
            return vector
    raise KeyError(f"bootstrap vector not found: {name}")


def _run_negative_operation(vector: dict[str, object], *, vectors_dir: Path) -> None:
    operation = str(vector["operation"])
    if operation == "pairing_validate":
        _validate_pairing_request_for_invite(vector)
        return
    if operation == "pairing_request_decode":
        _pairing_request_from_bytes(bytes.fromhex(str(vector["cbor_hex"])))
        return
    if operation == "pairing_response_decode":
        _pairing_response_from_bytes(bytes.fromhex(str(vector["cbor_hex"])))
        return
    if operation == "invite_verify":
        if verify_invite_vector(vector):
            raise ValueError("invite signature verified unexpectedly")
        raise ValueError("invite signature rejected")
    if operation == "outer_blob_decode":
        relay = vector.get("relay_json")
        if not isinstance(relay, dict):
            raise ValueError("invalid relay_json")
        _outer_blob_from_relay_json(relay)
        return
    if operation in {
        "ratchet_decrypt",
        "ratchet_decrypt_duplicate",
        "ratchet_decrypt_skip_gap",
        "ratchet_decrypt_tampered",
    }:
        bootstrap = _load_bootstrap_vector(vectors_dir, str(vector["bootstrap_vector"]))
        side = str(vector.get("side", "bob"))
        local, peer = _RatchetSession.from_bootstrap_vector(bootstrap, side=side)
        if operation == "ratchet_decrypt":
            local.decrypt(bytes.fromhex(str(vector["payload_hex"])))
            return
        if operation == "ratchet_decrypt_duplicate":
            message = peer.encrypt(b"negative-vector-once")
            local.decrypt(message)
            local.decrypt(message)
            return
        if operation == "ratchet_decrypt_skip_gap":
            import secrets

            first = peer.encrypt(b"negative-vector-first")
            local.decrypt(first)
            peer_public = first[len(RATCHET_MAGIC) : len(RATCHET_MAGIC) + 32]
            future_n = local.recv_n + MAX_SKIP_GAP + 1
            forged = (
                RATCHET_MAGIC
                + peer_public
                + struct.pack(">II", 0, future_n)
                + secrets.token_bytes(32)
            )
            local.decrypt(forged)
            return
        message = peer.encrypt(b"negative-vector-tampered")
        tampered = bytearray(message)
        tampered[-1] ^= 0xFF
        local.decrypt(bytes(tampered))
        return
    raise ValueError(f"unknown negative vector operation: {operation}")


def verify_negative_vector(vector: dict[str, object], *, vectors_dir: str | Path) -> bool:
    """Return True when the vector is rejected as expected."""
    root = Path(vectors_dir)
    try:
        _run_negative_operation(vector, vectors_dir=root)
    except Exception as exc:
        if not vector.get("must_reject", True):
            return False
        expected = vector.get("error_contains")
        if expected and str(expected) not in str(exc):
            return False
        return True
    return False


def verify_all_negative_vectors(vectors_dir: str | Path) -> None:
    root = Path(vectors_dir)
    negative_dir = root / "negative"
    if not negative_dir.is_dir():
        raise FileNotFoundError(f"negative vector directory missing: {negative_dir}")
    for path in sorted(negative_dir.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not verify_negative_vector(item, vectors_dir=root):
                raise AssertionError(f"negative vector failed: {path.name} ({item.get('name', 'unnamed')})")


def verify_all_vectors(vectors_dir: str | Path) -> None:
    root = Path(vectors_dir)
    checks = [
        ("hybrid_kex.json", verify_hybrid_kex_vector, True),
        ("mailbox_tag.json", verify_mailbox_tag_vector, False),
        ("invite.json", verify_invite_vector, False),
        ("delivery_profile.json", verify_delivery_profile_vector, False),
        ("inner_message.json", verify_inner_message_vector, False),
        ("inner_receipt.json", verify_inner_receipt_vector, False),
        ("outer_blob.json", verify_outer_blob_vector, False),
        ("pairing_transcript.json", verify_pairing_transcript_vector, True),
        ("double_ratchet.json", verify_double_ratchet_vector, True),
    ]
    for filename, verifier, is_array in checks:
        data = json.loads((root / filename).read_text(encoding="utf-8"))
        items = data if is_array else [data]
        for item in items:
            if not verifier(item):
                raise AssertionError(f"vector failed: {filename} ({item.get('name', 'unnamed')})")
    verify_all_negative_vectors(root)
