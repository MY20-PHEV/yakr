from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.identity import Contact, Identity
from yakr_core.privacy import PrivacyMetrics
from yakr_core.routing import RouteState
from yakr_core.store import FileLocalStore


def _derive_fernet(passphrase: str, *, salt: bytes) -> Fernet:
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
    ).derive(passphrase.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(key))


@dataclass
class MobileStore:
    """Encrypted SQLite-backed store for mobile clients."""

    db_path: Path
    passphrase: str
    _fernet: Fernet | None = None

    def __post_init__(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        self._fernet = self._load_or_create_fernet()

    @property
    def file_store(self) -> FileLocalStore:
        return FileLocalStore(self.db_path.parent / "yakr_data")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS crypto_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    salt BLOB NOT NULL,
                    wrapped_key BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS encrypted_kv (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS worker_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def _load_or_create_fernet(self) -> Fernet:
        with self._connect() as conn:
            row = conn.execute("SELECT salt, wrapped_key FROM crypto_meta WHERE id = 1").fetchone()
        if row is None:
            salt = b"yakr-mobile-salt-v1"
            fernet = _derive_fernet(self.passphrase, salt=salt)
            wrapped = fernet.encrypt(b"ok")
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO crypto_meta (id, salt, wrapped_key) VALUES (1, ?, ?)",
                    (salt, wrapped),
                )
                conn.commit()
            return fernet
        salt, wrapped = row
        fernet = _derive_fernet(self.passphrase, salt=bytes(salt))
        try:
            fernet.decrypt(bytes(wrapped))
        except InvalidToken as exc:
            raise ValueError("invalid mobile store passphrase") from exc
        return fernet

    def _encrypt(self, payload: bytes) -> bytes:
        assert self._fernet is not None
        return self._fernet.encrypt(payload)

    def _decrypt(self, payload: bytes) -> bytes:
        assert self._fernet is not None
        return self._fernet.decrypt(payload)

    def put_blob(self, key: str, data: bytes) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO encrypted_kv (key, value) VALUES (?, ?)",
                (key, self._encrypt(data)),
            )
            conn.commit()

    def get_blob(self, key: str) -> bytes | None:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM encrypted_kv WHERE key = ?", (key,)).fetchone()
        if row is None:
            return None
        return self._decrypt(bytes(row[0]))

    def save_identity(self, identity: Identity) -> None:
        self.file_store.save_identity(identity)
        self.put_blob("identity", json.dumps(identity.to_dict()).encode("utf-8"))

    def load_identity(self) -> Identity | None:
        encrypted = self.get_blob("identity")
        if encrypted is None:
            return self.file_store.load_identity()
        return Identity.from_dict(json.loads(encrypted.decode("utf-8")))

    def save_contact(self, contact: Contact) -> None:
        self.file_store.save_contact(contact)
        self.put_blob(f"contact:{contact.name}", json.dumps(contact.to_dict()).encode("utf-8"))

    def get_contact(self, name: str) -> Contact | None:
        encrypted = self.get_blob(f"contact:{name}")
        if encrypted is None:
            return self.file_store.get_contact(name)
        return Contact.from_dict(json.loads(encrypted.decode("utf-8")))

    def list_contacts(self) -> list[str]:
        return self.file_store.list_contacts()

    def save_worker_state(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO worker_state (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

    def load_worker_state(self, key: str, default: str = "") -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM worker_state WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else default

    def save_privacy_metrics(self, metrics: PrivacyMetrics) -> None:
        self.file_store.save_privacy_metrics(metrics)

    def load_privacy_metrics(self) -> PrivacyMetrics:
        return self.file_store.load_privacy_metrics()

    def save_route_state(self, contact_name: str, state: RouteState) -> None:
        self.file_store.save_route_state(contact_name, state)

    def load_route_state(self, contact_name: str) -> RouteState:
        return self.file_store.load_route_state(contact_name)

    def save_inbound_message(self, contact_name: str, seq: int, body: str) -> None:
        self.file_store.save_inbound_message(contact_name, seq, body)

    def list_inbound_messages(self, contact_name: str) -> list[tuple[int, str]]:
        return self.file_store.list_inbound_messages(contact_name)

    def save_outbound_pending(self, contact_name: str, msg_id: str, seq: int, body: str) -> None:
        self.file_store.save_outbound_pending(contact_name, msg_id, seq, body)

    def mark_outbound_delivered(self, contact_name: str, msg_id: str) -> bool:
        return self.file_store.mark_outbound_delivered(contact_name, msg_id)

    def list_outbound_pending(self, contact_name: str) -> list[tuple[str, int, str]]:
        return self.file_store.list_outbound_pending(contact_name)

    def save_local_profile(self, profile: DeliveryProfile) -> None:
        self.file_store.save_local_profile(profile)

    def load_local_profile(self) -> DeliveryProfile | None:
        return self.file_store.load_local_profile()
