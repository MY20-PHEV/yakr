from __future__ import annotations

import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from yakr_core.crypto import hkdf_derive, x25519_shared_secret, xchacha_decrypt, xchacha_encrypt

RATCHET_MAGIC = b"YKDR2"
MAX_SKIP_GAP = 128
MAX_SKIPPED_KEYS = 256
ROOT_INFO = b"yakr/v1.0/double-ratchet-root"
RK_INFO = b"yakr/v1.0/double-ratchet-rk"
CK_INFO = b"yakr/v1.0/double-ratchet-ck"
SEND_CHAIN_INFO = b"yakr/v1.0/double-ratchet-send"
RECV_CHAIN_INFO = b"yakr/v1.0/double-ratchet-recv"


def _kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    material = hkdf_derive(root_key, RK_INFO, salt=dh_output, length=64)
    return material[:32], material[32:]


def _kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    material = hkdf_derive(chain_key, CK_INFO, length=64)
    return material[:32], material[32:]


def _pub_bytes(key: x25519.X25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _load_private(raw: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(raw)


@dataclass
class RatchetState:
    """X25519 double ratchet with symmetric send/recv chains."""

    root_key: bytes
    dh_self_private: bytes
    dh_self_public: bytes
    dh_peer_public: bytes | None = None
    send_chain_key: bytes | None = None
    recv_chain_key: bytes | None = None
    send_n: int = 0
    recv_n: int = 0
    prev_send_n: int = 0
    skipped_keys: dict[str, str] = field(default_factory=dict)
    hybrid: bool = False
    pending_pairing_dh_ratchet_peer: bytes | None = None

    @classmethod
    def from_master(
        cls,
        master_secret: bytes,
        *,
        is_initiator: bool,
        hybrid: bool = False,
        ratchet_private: x25519.X25519PrivateKey | None = None,
    ) -> RatchetState:
        root_key = hkdf_derive(master_secret, ROOT_INFO)
        send_chain = hkdf_derive(root_key, SEND_CHAIN_INFO)
        recv_chain = hkdf_derive(root_key, RECV_CHAIN_INFO)
        if not is_initiator:
            send_chain, recv_chain = recv_chain, send_chain
        if ratchet_private is None:
            ratchet_private = x25519.X25519PrivateKey.generate()
        dh_public = _pub_bytes(ratchet_private)
        return cls(
            root_key=root_key,
            dh_self_private=ratchet_private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            dh_self_public=dh_public,
            send_chain_key=send_chain,
            recv_chain_key=recv_chain,
            hybrid=hybrid,
        )

    def to_dict(self) -> dict[str, str | int | bool | dict[str, str]]:
        import base64

        return {
            "version": 2,
            "root_key": base64.urlsafe_b64encode(self.root_key).decode("ascii").rstrip("="),
            "dh_self_private": base64.urlsafe_b64encode(self.dh_self_private).decode("ascii").rstrip("="),
            "dh_self_public": base64.urlsafe_b64encode(self.dh_self_public).decode("ascii").rstrip("="),
            "dh_peer_public": (
                base64.urlsafe_b64encode(self.dh_peer_public).decode("ascii").rstrip("=")
                if self.dh_peer_public is not None
                else ""
            ),
            "send_chain_key": (
                base64.urlsafe_b64encode(self.send_chain_key).decode("ascii").rstrip("=")
                if self.send_chain_key is not None
                else ""
            ),
            "recv_chain_key": (
                base64.urlsafe_b64encode(self.recv_chain_key).decode("ascii").rstrip("=")
                if self.recv_chain_key is not None
                else ""
            ),
            "send_n": self.send_n,
            "recv_n": self.recv_n,
            "prev_send_n": self.prev_send_n,
            "skipped_keys": self.skipped_keys,
            "hybrid": self.hybrid,
            "pending_pairing_dh_ratchet_peer": (
                base64.urlsafe_b64encode(self.pending_pairing_dh_ratchet_peer).decode("ascii").rstrip("=")
                if self.pending_pairing_dh_ratchet_peer is not None
                else ""
            ),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | int | bool | dict[str, str]]) -> RatchetState:
        import base64

        def dec(value: str) -> bytes:
            if not value:
                return b""
            padding = "=" * (-len(value) % 4)
            return base64.urlsafe_b64decode(value + padding)

        if int(payload.get("version", 0)) != 2:
            raise ValueError("unsupported ratchet version; re-pair required")

        peer = dec(str(payload.get("dh_peer_public", "")))
        send_chain = dec(str(payload.get("send_chain_key", "")))
        recv_chain = dec(str(payload.get("recv_chain_key", "")))
        skipped = payload.get("skipped_keys", {})
        if not isinstance(skipped, dict):
            skipped = {}
        pending_peer = dec(str(payload.get("pending_pairing_dh_ratchet_peer", "")))
        return cls(
            root_key=dec(str(payload["root_key"])),
            dh_self_private=dec(str(payload["dh_self_private"])),
            dh_self_public=dec(str(payload["dh_self_public"])),
            dh_peer_public=peer or None,
            send_chain_key=send_chain or None,
            recv_chain_key=recv_chain or None,
            send_n=int(payload.get("send_n", 0)),
            recv_n=int(payload.get("recv_n", 0)),
            prev_send_n=int(payload.get("prev_send_n", 0)),
            skipped_keys={str(k): str(v) for k, v in skipped.items()},
            hybrid=bool(payload.get("hybrid", False)),
            pending_pairing_dh_ratchet_peer=pending_peer or None,
        )

    def _skip_key(self, dh_public: bytes, n: int) -> bytes:
        import base64

        key_id = f"{dh_public.hex()}:{n}"
        stored = self.skipped_keys.get(key_id)
        if stored is None:
            raise KeyError(key_id)
        padding = "=" * (-len(stored) % 4)
        return base64.urlsafe_b64decode(stored + padding)

    def _store_skip(self, dh_public: bytes, n: int, message_key: bytes) -> None:
        import base64

        key_id = f"{dh_public.hex()}:{n}"
        self.skipped_keys[key_id] = base64.urlsafe_b64encode(message_key).decode("ascii").rstrip("=")

    def _pairing_send_init(self, peer_public: bytes) -> None:
        """Initiator first send: derive send chain without recv transition."""
        if len(peer_public) != 32:
            raise ValueError("peer ratchet public key must be 32 bytes")
        self.dh_peer_public = peer_public
        dh_self = _load_private(self.dh_self_private)
        dh_output = x25519_shared_secret(dh_self, peer_public)
        root_key, _recv_unused = _kdf_rk(self.root_key, dh_output)

        new_private = x25519.X25519PrivateKey.generate()
        self.dh_self_private = new_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.dh_self_public = _pub_bytes(new_private)
        dh_output = x25519_shared_secret(new_private, peer_public)
        self.root_key, self.send_chain_key = _kdf_rk(root_key, dh_output)
        self.prev_send_n = self.send_n
        self.send_n = 0

    def _pairing_recv_init(self, peer_public: bytes) -> None:
        """Responder pairing: align recv chain with initiator's post-pairing send chain."""
        if len(peer_public) != 32:
            raise ValueError("peer ratchet public key must be 32 bytes")
        self.dh_peer_public = peer_public
        dh_self = _load_private(self.dh_self_private)
        dh_output = x25519_shared_secret(dh_self, peer_public)
        self.root_key, self.recv_chain_key = _kdf_rk(self.root_key, dh_output)
        self.recv_n = 0

    def _dh_ratchet(self, peer_public: bytes) -> None:
        self.skipped_keys.clear()
        self.dh_peer_public = peer_public
        dh_self = _load_private(self.dh_self_private)
        dh_output = x25519_shared_secret(dh_self, peer_public)
        self.root_key, self.recv_chain_key = _kdf_rk(self.root_key, dh_output)
        self.recv_n = 0

        new_private = x25519.X25519PrivateKey.generate()
        self.dh_self_private = new_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.dh_self_public = _pub_bytes(new_private)
        dh_output = x25519_shared_secret(new_private, peer_public)
        self.root_key, self.send_chain_key = _kdf_rk(self.root_key, dh_output)
        self.prev_send_n = self.send_n
        self.send_n = 0

    def _header_aad(self, *, prev_n: int, message_n: int) -> bytes:
        return RATCHET_MAGIC + self.dh_self_public + struct.pack(">II", prev_n, message_n)

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.pending_pairing_dh_ratchet_peer is not None:
            peer = self.pending_pairing_dh_ratchet_peer
            self.pending_pairing_dh_ratchet_peer = None
            self._pairing_send_init(peer)
        if self.send_chain_key is None:
            raise ValueError("send chain not initialized")
        message_key, self.send_chain_key = _kdf_ck(self.send_chain_key)
        aad = self._header_aad(prev_n=self.prev_send_n, message_n=self.send_n)
        ciphertext = xchacha_encrypt(message_key, plaintext, associated_data=aad)
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
                mk, self.recv_chain_key = _kdf_ck(self.recv_chain_key)
                self._store_skip(peer_public, self.recv_n, mk)
                self.recv_n += 1
            message_key, self.recv_chain_key = _kdf_ck(self.recv_chain_key)
            self.recv_n = message_n + 1

        aad = RATCHET_MAGIC + peer_public + struct.pack(">II", prev_n, message_n)
        plaintext = xchacha_decrypt(message_key, ciphertext, associated_data=aad)
        return plaintext
