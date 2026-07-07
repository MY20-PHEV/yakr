from __future__ import annotations

from dataclasses import dataclass

from yakr_core.crypto import hkdf_derive, xchacha_decrypt, xchacha_encrypt


@dataclass
class RatchetState:
    send_chain: bytes
    recv_chain: bytes
    send_n: int = 0
    recv_n: int = 0

    @classmethod
    def from_master(cls, master_secret: bytes, *, is_initiator: bool) -> RatchetState:
        send_chain = hkdf_derive(master_secret, b"yakr/v0.4/ratchet-send")
        recv_chain = hkdf_derive(master_secret, b"yakr/v0.4/ratchet-recv")
        if not is_initiator:
            send_chain, recv_chain = recv_chain, send_chain
        return cls(send_chain=send_chain, recv_chain=recv_chain)

    def to_dict(self) -> dict[str, str | int]:
        import base64

        return {
            "send_chain": base64.urlsafe_b64encode(self.send_chain).decode("ascii").rstrip("="),
            "recv_chain": base64.urlsafe_b64encode(self.recv_chain).decode("ascii").rstrip("="),
            "send_n": self.send_n,
            "recv_n": self.recv_n,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | int]) -> RatchetState:
        import base64

        def dec(value: str) -> bytes:
            padding = "=" * (-len(value) % 4)
            return base64.urlsafe_b64decode(value + padding)

        return cls(
            send_chain=dec(str(payload["send_chain"])),
            recv_chain=dec(str(payload["recv_chain"])),
            send_n=int(payload.get("send_n", 0)),
            recv_n=int(payload.get("recv_n", 0)),
        )

    def next_send_key(self) -> bytes:
        key = hkdf_derive(self.send_chain, b"msg" + self.send_n.to_bytes(4, "big"))
        self.send_n += 1
        if self.send_n % 32 == 0:
            self.send_chain = hkdf_derive(self.send_chain, b"step")
        return key

    def try_recv_key(self, seq_hint: int) -> bytes:
        return hkdf_derive(self.recv_chain, b"msg" + seq_hint.to_bytes(4, "big"))

    def advance_recv(self, seq_hint: int) -> None:
        if seq_hint >= self.recv_n:
            self.recv_n = seq_hint + 1
        if self.recv_n % 32 == 0:
            self.recv_chain = hkdf_derive(self.recv_chain, b"step")

    def encrypt(self, plaintext: bytes) -> bytes:
        return xchacha_encrypt(self.next_send_key(), plaintext)

    def decrypt_at(self, ciphertext: bytes, *, seq_hint: int) -> bytes:
        return xchacha_decrypt(self.try_recv_key(seq_hint), ciphertext)

    def commit_recv(self, seq_hint: int) -> None:
        self.advance_recv(seq_hint)
