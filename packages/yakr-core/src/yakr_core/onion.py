from __future__ import annotations

import cbor2

from yakr_core.crypto import xchacha_decrypt, xchacha_encrypt
from yakr_core.message import OuterBlob


def encrypt_layer(wrap_secret: bytes, plaintext: bytes) -> bytes:
    return xchacha_encrypt(wrap_secret, plaintext)


def decrypt_layer(wrap_secret: bytes, payload: bytes) -> bytes:
    return xchacha_decrypt(wrap_secret, payload)


def encode_mailbox_instruction(outer: OuterBlob) -> bytes:
    return cbor2.dumps(
        {
            "mailbox_tag": outer.mailbox_tag,
            "expires_at": outer.expires_at,
            "ciphertext": outer.ciphertext,
        }
    )


def decode_mailbox_instruction(payload: bytes) -> OuterBlob:
    data = cbor2.loads(payload)
    return OuterBlob(
        version=1,
        mailbox_tag=bytes(data["mailbox_tag"]),
        expires_at=int(data["expires_at"]),
        ciphertext=bytes(data["ciphertext"]),
    )


def encode_forward_instruction(next_relay_ingest_url: str, inner_ciphertext: bytes) -> bytes:
    return cbor2.dumps(
        {
            "next_relay": next_relay_ingest_url,
            "inner": inner_ciphertext,
        }
    )


def decode_forward_instruction(payload: bytes) -> tuple[str, bytes]:
    data = cbor2.loads(payload)
    return str(data["next_relay"]), bytes(data["inner"])


def build_onion_packet(
    *,
    entry_wrap_secret: bytes,
    mailbox_wrap_secret: bytes,
    entry_relay_url: str,
    mailbox_relay_url: str,
    outer: OuterBlob,
) -> bytes:
    mailbox_plain = encode_mailbox_instruction(outer)
    mailbox_cipher = encrypt_layer(mailbox_wrap_secret, mailbox_plain)

    forward_plain = encode_forward_instruction(f"{mailbox_relay_url}/v1/ingest", mailbox_cipher)
    entry_cipher = encrypt_layer(entry_wrap_secret, forward_plain)

    return cbor2.dumps({"version": 1, "entry_ciphertext": entry_cipher})


def decode_entry_packet(packet: bytes, entry_wrap_secret: bytes) -> tuple[str, bytes]:
    data = cbor2.loads(packet)
    forward_plain = decrypt_layer(entry_wrap_secret, bytes(data["entry_ciphertext"]))
    return decode_forward_instruction(forward_plain)


def decode_mailbox_packet(inner_ciphertext: bytes, mailbox_wrap_secret: bytes) -> OuterBlob:
    mailbox_plain = decrypt_layer(mailbox_wrap_secret, inner_ciphertext)
    return decode_mailbox_instruction(mailbox_plain)
