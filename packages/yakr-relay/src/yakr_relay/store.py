from __future__ import annotations

import base64
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


@dataclass
class StoredBlob:
    mailbox_tag: bytes
    expires_at: int
    ciphertext: bytes
    stored_at: int


class BlobStore:
    def __init__(
        self,
        root: Path,
        *,
        max_blob_size: int = 64 * 1024,
        max_blobs_per_tag: int = 256,
    ) -> None:
        self.root = root
        self.max_blob_size = max_blob_size
        self.max_blobs_per_tag = max_blobs_per_tag
        self.root.mkdir(parents=True, exist_ok=True)
        self._db_path = self.root / "relay.db"
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mailbox_tag BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL,
                    stored_at INTEGER NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_blobs_tag ON blobs(mailbox_tag)")
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def store(self, mailbox_tag: bytes, expires_at: int, ciphertext: bytes) -> None:
        if len(mailbox_tag) != 32:
            raise ValueError("mailbox_tag must be 32 bytes")
        if len(ciphertext) > self.max_blob_size:
            raise ValueError("blob too large")
        now_ms = int(time.time() * 1000)
        if expires_at <= now_ms:
            raise ValueError("blob already expired")

        with self._lock, self._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM blobs WHERE mailbox_tag = ? AND expires_at > ?",
                (mailbox_tag, now_ms),
            ).fetchone()[0]
            if count >= self.max_blobs_per_tag:
                raise ValueError("mailbox tag blob limit exceeded")

            conn.execute(
                "INSERT INTO blobs (mailbox_tag, expires_at, ciphertext, stored_at) VALUES (?, ?, ?, ?)",
                (mailbox_tag, expires_at, ciphertext, now_ms),
            )
            conn.commit()

    def fetch(self, mailbox_tag: bytes) -> list[StoredBlob]:
        now_ms = int(time.time() * 1000)
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT mailbox_tag, expires_at, ciphertext, stored_at
                FROM blobs
                WHERE mailbox_tag = ? AND expires_at > ?
                ORDER BY stored_at ASC
                """,
                (mailbox_tag, now_ms),
            ).fetchall()
        return [
            StoredBlob(
                mailbox_tag=row[0],
                expires_at=row[1],
                ciphertext=row[2],
                stored_at=row[3],
            )
            for row in rows
        ]

    def sweep_expired(self) -> int:
        now_ms = int(time.time() * 1000)
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM blobs WHERE expires_at <= ?", (now_ms,))
            conn.commit()
            return cursor.rowcount

    def to_json_blob(self, blob: StoredBlob) -> dict[str, str | int]:
        return {
            "mailbox_tag": _b64encode(blob.mailbox_tag),
            "expires_at": blob.expires_at,
            "ciphertext": _b64encode(blob.ciphertext),
            "stored_at": blob.stored_at,
        }
