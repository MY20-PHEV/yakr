from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.ephemeral import MESSAGE_TTL_MS
from yakr_core.privacy import PrivacyMetrics
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.routing import RouteState

if TYPE_CHECKING:
    pass


class LocalStore(Protocol):
    def load_identity(self) -> Identity | None: ...
    def save_identity(self, identity: Identity) -> None: ...
    def get_contact(self, name: str) -> Contact | None: ...
    def save_contact(self, contact: Contact) -> None: ...
    def list_contacts(self) -> list[str]: ...
    def save_inbound_message(
        self,
        contact_name: str,
        inner: "InnerMessage",
        *,
        identity: Identity,
    ) -> None: ...

    def list_inbound_messages(self, contact_name: str, identity: Identity) -> list[tuple[int, str]]: ...

    def sweep_expired_messages(self) -> int: ...

    def save_outbound_pending(
        self, contact_name: str, msg_id: str, seq: int, body: str
    ) -> None: ...

    def mark_outbound_delivered(self, contact_name: str, msg_id: str) -> bool: ...

    def list_outbound_pending(self, contact_name: str) -> list[tuple[str, int, str]]: ...

    def sweep_expired_outbound(self) -> int: ...

    def load_route_state(self, contact_name: str) -> RouteState: ...

    def save_route_state(self, contact_name: str, state: RouteState) -> None: ...

    def save_presence(self, payload: "PresencePayload", *, source_contact: str) -> None: ...

    def load_presence(self, operator_name: str) -> "PresencePayload | None": ...

    def list_presences(self) -> list["PresencePayload"]: ...

    def save_pending_receipt(
        self,
        contact_name: str,
        delivered_id: str,
        *,
        route: str | None = None,
    ) -> None: ...

    def list_pending_receipts(self, contact_name: str | None = None) -> list[tuple[str, str, str | None]]: ...

    def delete_pending_receipt(self, contact_name: str, delivered_id: str) -> bool: ...


@dataclass
class FileLocalStore:
    root: Path

    @property
    def identity_path(self) -> Path:
        return self.root / "identity.json"

    @property
    def contacts_dir(self) -> Path:
        return self.root / "contacts"

    @property
    def db_path(self) -> Path:
        return self.root / "messages.db"

    def load_identity(self) -> Identity | None:
        if not self.identity_path.exists():
            return None
        return Identity.load(self.identity_path)

    def save_identity(self, identity: Identity) -> None:
        identity.save(self.identity_path)
        self._export_public_bundle(identity)

    def _export_public_bundle(self, identity: Identity) -> None:
        bundle_path = self.root / "public.json"
        bundle_path.write_text(json.dumps(export_public_bundle(identity), indent=2), encoding="utf-8")

    def contact_path(self, name: str) -> Path:
        return self.contacts_dir / f"{name}.json"

    def get_contact(self, name: str) -> Contact | None:
        path = self.contact_path(name)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        return Contact.from_dict(payload)

    def save_contact(self, contact: Contact) -> None:
        self.contacts_dir.mkdir(parents=True, exist_ok=True)
        self.contact_path(contact.name).write_text(
            json.dumps(contact.to_dict(), indent=2),
            encoding="utf-8",
        )

    def list_contacts(self) -> list[str]:
        if not self.contacts_dir.exists():
            return []
        return sorted(path.stem for path in self.contacts_dir.glob("*.json"))

    def _connect(self) -> sqlite3.Connection:
        self.root.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        self._ensure_message_schema(conn)
        return conn

    def _ensure_message_schema(self, conn: sqlite3.Connection) -> None:
        inbound_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(inbound_messages)").fetchall()
        }
        if inbound_columns and "local_ciphertext" not in inbound_columns:
            conn.execute("DROP TABLE inbound_messages")
            inbound_columns = set()

        if not inbound_columns:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS inbound_messages (
                    contact_name TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    valid_until INTEGER NOT NULL,
                    received_at INTEGER NOT NULL,
                    local_ciphertext BLOB NOT NULL,
                    PRIMARY KEY (contact_name, seq)
                )
                """
            )

        outbound_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(outbound_pending)").fetchall()
        }
        if outbound_columns and "created_at" not in outbound_columns:
            conn.execute("DROP TABLE outbound_pending")
            outbound_columns = set()

        if not outbound_columns:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS outbound_pending (
                    contact_name TEXT NOT NULL,
                    msg_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    body TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    valid_until INTEGER NOT NULL,
                    PRIMARY KEY (contact_name, msg_id)
                )
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS relay_presence (
                operator_name TEXT PRIMARY KEY,
                reachable_url TEXT NOT NULL,
                relay_active INTEGER NOT NULL,
                valid_until INTEGER NOT NULL,
                source_contact TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_receipts (
                contact_name TEXT NOT NULL,
                delivered_id TEXT NOT NULL,
                route TEXT,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (contact_name, delivered_id)
            )
            """
        )
        conn.commit()

    def save_inbound_message(
        self,
        contact_name: str,
        inner: "InnerMessage",
        *,
        identity: Identity,
    ) -> None:
        from yakr_core.message import InnerMessage
        from yakr_core.session import wrap_local_ciphertext

        now = int(time.time() * 1000)
        wrapped = wrap_local_ciphertext(identity, inner.to_bytes())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO inbound_messages
                (contact_name, seq, valid_until, received_at, local_ciphertext)
                VALUES (?, ?, ?, ?, ?)
                """,
                (contact_name, inner.seq, inner.valid_until, now, wrapped),
            )
            conn.commit()

    def list_inbound_messages(self, contact_name: str, identity: Identity) -> list[tuple[int, str]]:
        from yakr_core.ephemeral import enforce_message_ttl
        from yakr_core.message import InnerMessage
        from yakr_core.session import unwrap_local_ciphertext

        now = int(time.time() * 1000)
        results: list[tuple[int, str]] = []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT seq, valid_until, local_ciphertext
                FROM inbound_messages
                WHERE contact_name = ? AND valid_until > ?
                ORDER BY seq
                """,
                (contact_name, now),
            ).fetchall()
        for _seq, valid_until, wrapped in rows:
            try:
                inner = InnerMessage.from_bytes(unwrap_local_ciphertext(identity, wrapped))
                enforce_message_ttl(inner.valid_until, now_ms=now)
            except Exception:
                continue
            if inner.type == "text":
                results.append((inner.seq, inner.body))
        return results

    def sweep_expired_messages(self) -> int:
        now = int(time.time() * 1000)
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM inbound_messages WHERE valid_until <= ? OR received_at <= ?",
                (now, now - MESSAGE_TTL_MS),
            )
            conn.commit()
            return cursor.rowcount

    def save_outbound_pending(
        self, contact_name: str, msg_id: str, seq: int, body: str
    ) -> None:
        from yakr_core.ephemeral import message_valid_until

        now = int(time.time() * 1000)
        valid_until = message_valid_until(created_at_ms=now)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO outbound_pending
                (contact_name, msg_id, seq, body, created_at, valid_until)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (contact_name, msg_id, seq, body, now, valid_until),
            )
            conn.commit()

    def mark_outbound_delivered(self, contact_name: str, msg_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM outbound_pending WHERE contact_name = ? AND msg_id = ?",
                (contact_name, msg_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def list_outbound_pending(self, contact_name: str) -> list[tuple[str, int, str]]:
        now = int(time.time() * 1000)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT msg_id, seq, body FROM outbound_pending
                WHERE contact_name = ? AND valid_until > ?
                ORDER BY seq
                """,
                (contact_name, now),
            ).fetchall()
        return [(str(msg_id), int(seq), str(body)) for msg_id, seq, body in rows]

    def sweep_expired_outbound(self) -> int:
        now = int(time.time() * 1000)
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM outbound_pending WHERE valid_until <= ? OR created_at <= ?",
                (now, now - MESSAGE_TTL_MS),
            )
            conn.commit()
            return cursor.rowcount

    @property
    def route_state_path(self) -> Path:
        return self.root / "route_state.json"

    def load_route_state(self, contact_name: str) -> RouteState:
        if not self.route_state_path.exists():
            return RouteState()
        payload = json.loads(self.route_state_path.read_text(encoding="utf-8"))
        contact_state = payload.get(contact_name, {})
        return RouteState.from_dict(contact_state)

    def save_route_state(self, contact_name: str, state: RouteState) -> None:
        payload: dict[str, dict[str, str | None]] = {}
        if self.route_state_path.exists():
            payload = json.loads(self.route_state_path.read_text(encoding="utf-8"))
        payload[contact_name] = state.to_dict()
        self.route_state_path.parent.mkdir(parents=True, exist_ok=True)
        self.route_state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @property
    def local_profile_path(self) -> Path:
        return self.root / "profiles" / "local.profile"

    def load_local_profile(self) -> DeliveryProfile | None:
        if not self.local_profile_path.exists():
            return None
        return DeliveryProfile.from_b64(self.local_profile_path.read_text(encoding="utf-8").strip())

    def save_local_profile(self, profile: DeliveryProfile) -> None:
        self.local_profile_path.parent.mkdir(parents=True, exist_ok=True)
        self.local_profile_path.write_text(profile.to_b64(), encoding="utf-8")

    @property
    def pending_pairing_path(self) -> Path:
        return self.root / "pending_pairing.json"

    def save_pending_pairing(self, session) -> None:
        from yakr_core.pairing import PendingPairingSession

        if not isinstance(session, PendingPairingSession):
            raise TypeError("expected PendingPairingSession")
        self.pending_pairing_path.parent.mkdir(parents=True, exist_ok=True)
        self.pending_pairing_path.write_text(json.dumps(session.to_dict(), indent=2), encoding="utf-8")

    def load_pending_pairing(self):
        from yakr_core.pairing import PendingPairingSession

        if not self.pending_pairing_path.exists():
            return None
        payload = json.loads(self.pending_pairing_path.read_text(encoding="utf-8"))
        return PendingPairingSession.from_dict(payload)

    def clear_pending_pairing(self) -> None:
        if self.pending_pairing_path.exists():
            self.pending_pairing_path.unlink()

    @property
    def privacy_metrics_path(self) -> Path:
        return self.root / "privacy_metrics.json"

    def load_privacy_metrics(self) -> PrivacyMetrics:
        if not self.privacy_metrics_path.exists():
            return PrivacyMetrics()
        payload = json.loads(self.privacy_metrics_path.read_text(encoding="utf-8"))
        return PrivacyMetrics.from_dict(payload)

    def save_privacy_metrics(self, metrics: PrivacyMetrics) -> None:
        self.privacy_metrics_path.parent.mkdir(parents=True, exist_ok=True)
        self.privacy_metrics_path.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")

    def save_presence(self, payload: "PresencePayload", *, source_contact: str) -> None:
        from yakr_core.presence import PresencePayload

        if not isinstance(payload, PresencePayload):
            raise TypeError("expected PresencePayload")
        now = int(time.time() * 1000)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO relay_presence
                (operator_name, reachable_url, relay_active, valid_until, source_contact, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.operator_name,
                    payload.reachable_url.rstrip("/"),
                    1 if payload.relay_active else 0,
                    payload.valid_until,
                    source_contact,
                    now,
                ),
            )
            conn.commit()

    def load_presence(self, operator_name: str) -> "PresencePayload | None":
        from yakr_core.presence import PresencePayload

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT reachable_url, relay_active, valid_until
                FROM relay_presence
                WHERE operator_name = ?
                """,
                (operator_name,),
            ).fetchone()
        if row is None:
            return None
        url, active, valid_until = row
        return PresencePayload(
            operator_name=operator_name,
            reachable_url=str(url),
            relay_active=bool(active),
            valid_until=int(valid_until),
        )

    def list_presences(self) -> list["PresencePayload"]:
        from yakr_core.presence import PresencePayload

        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT operator_name, reachable_url, relay_active, valid_until
                FROM relay_presence
                ORDER BY operator_name
                """
            ).fetchall()
        return [
            PresencePayload(
                operator_name=str(name),
                reachable_url=str(url),
                relay_active=bool(active),
                valid_until=int(valid_until),
            )
            for name, url, active, valid_until in rows
        ]

    def save_pending_receipt(
        self,
        contact_name: str,
        delivered_id: str,
        *,
        route: str | None = None,
    ) -> None:
        now = int(time.time() * 1000)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO pending_receipts
                (contact_name, delivered_id, route, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (contact_name, delivered_id, route, now),
            )
            conn.commit()

    def list_pending_receipts(self, contact_name: str | None = None) -> list[tuple[str, str, str | None]]:
        with self._connect() as conn:
            if contact_name is None:
                rows = conn.execute(
                    """
                    SELECT contact_name, delivered_id, route
                    FROM pending_receipts
                    ORDER BY created_at
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT contact_name, delivered_id, route
                    FROM pending_receipts
                    WHERE contact_name = ?
                    ORDER BY created_at
                    """,
                    (contact_name,),
                ).fetchall()
        return [(str(name), str(delivered_id), route) for name, delivered_id, route in rows]

    def delete_pending_receipt(self, contact_name: str, delivered_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM pending_receipts WHERE contact_name = ? AND delivered_id = ?",
                (contact_name, delivered_id),
            )
            conn.commit()
            return cursor.rowcount > 0
