from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from pathlib import Path

from yakr_core.pairing import invite_tag_for_secret
from yakr_relay.store import _b64decode, _b64encode


class PairingStore:
    """Opaque pairing mailbox on a group relay (rendezvous role)."""

    def __init__(self, root: Path, *, ttl_ms: int = 30 * 60 * 1000) -> None:
        self.root = root
        self.ttl_ms = ttl_ms
        self.root.mkdir(parents=True, exist_ok=True)
        self._db_path = self.root / "pairing.db"
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pairing_sessions (
                    invite_tag TEXT PRIMARY KEY,
                    invite_secret BLOB NOT NULL,
                    registered_at INTEGER NOT NULL,
                    request BLOB,
                    response BLOB,
                    consumed INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.commit()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def _now_ms(self) -> int:
        return int(time.time() * 1000)

    def sweep_expired(self) -> int:
        cutoff = self._now_ms() - self.ttl_ms
        with self._lock, self._connect() as conn:
            cursor = conn.execute("DELETE FROM pairing_sessions WHERE registered_at < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount

    def register(self, invite_secret: bytes) -> str:
        if len(invite_secret) != 32:
            raise ValueError("invite_secret must be 32 bytes")
        tag = invite_tag_for_secret(invite_secret)
        now = self._now_ms()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT consumed FROM pairing_sessions WHERE invite_tag = ?",
                (tag,),
            ).fetchone()
            if existing and existing[0]:
                raise ValueError("invite already consumed")
            conn.execute(
                """
                INSERT INTO pairing_sessions (invite_tag, invite_secret, registered_at, consumed)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(invite_tag) DO UPDATE SET
                    invite_secret = excluded.invite_secret,
                    registered_at = excluded.registered_at,
                    request = NULL,
                    response = NULL,
                    consumed = 0
                """,
                (tag, invite_secret, now),
            )
            conn.commit()
        return tag

    def store_request(self, invite_secret: bytes, request: bytes) -> str:
        tag = invite_tag_for_secret(invite_secret)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT consumed FROM pairing_sessions WHERE invite_tag = ?",
                (tag,),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO pairing_sessions (invite_tag, invite_secret, registered_at, request, consumed) VALUES (?, ?, ?, ?, 0)",
                    (tag, invite_secret, self._now_ms(), request),
                )
            elif row[0]:
                raise ValueError("invite already consumed")
            else:
                conn.execute(
                    "UPDATE pairing_sessions SET request = ? WHERE invite_tag = ?",
                    (request, tag),
                )
            conn.commit()
        return tag

    def get_pending_request(self, invite_tag: str) -> bytes | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT request, consumed FROM pairing_sessions WHERE invite_tag = ?",
                (invite_tag,),
            ).fetchone()
        if row is None or row[1]:
            return None
        return row[0]

    def store_response(self, invite_secret: bytes, response: bytes) -> str:
        tag = invite_tag_for_secret(invite_secret)
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT consumed FROM pairing_sessions WHERE invite_tag = ?",
                (tag,),
            ).fetchone()
            if row is None:
                raise ValueError("unknown invite session")
            if row[0]:
                raise ValueError("invite already consumed")
            conn.execute(
                "UPDATE pairing_sessions SET response = ?, consumed = 1 WHERE invite_tag = ?",
                (response, tag),
            )
            conn.commit()
        return tag

    def get_response(self, invite_tag: str) -> bytes | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT response, consumed FROM pairing_sessions WHERE invite_tag = ?",
                (invite_tag,),
            ).fetchone()
        if row is None or not row[1] or row[0] is None:
            return None
        return row[0]

    def verify_secret(self, invite_tag: str, invite_secret: bytes) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT invite_secret FROM pairing_sessions WHERE invite_tag = ?",
                (invite_tag,),
            ).fetchone()
        if row is None:
            raise ValueError("unknown invite session")
        if row[0] != invite_secret:
            raise ValueError("invite secret mismatch")
