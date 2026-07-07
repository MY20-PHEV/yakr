from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from yakr_core.delivery_profile import DeliveryProfile
from yakr_core.privacy import PrivacyMetrics
from yakr_core.identity import Contact, Identity, export_public_bundle
from yakr_core.routing import RouteState


class LocalStore(Protocol):
    def load_identity(self) -> Identity | None: ...
    def save_identity(self, identity: Identity) -> None: ...
    def get_contact(self, name: str) -> Contact | None: ...
    def save_contact(self, contact: Contact) -> None: ...
    def list_contacts(self) -> list[str]: ...
    def save_inbound_message(self, contact_name: str, seq: int, body: str) -> None: ...
    def list_inbound_messages(self, contact_name: str) -> list[tuple[int, str]]: ...

    def save_outbound_pending(
        self, contact_name: str, msg_id: str, seq: int, body: str
    ) -> None: ...

    def mark_outbound_delivered(self, contact_name: str, msg_id: str) -> bool: ...

    def list_outbound_pending(self, contact_name: str) -> list[tuple[str, int, str]]: ...

    def load_route_state(self, contact_name: str) -> RouteState: ...

    def save_route_state(self, contact_name: str, state: RouteState) -> None: ...


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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS inbound_messages (
                contact_name TEXT NOT NULL,
                seq INTEGER NOT NULL,
                body TEXT NOT NULL,
                PRIMARY KEY (contact_name, seq)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS outbound_pending (
                contact_name TEXT NOT NULL,
                msg_id TEXT NOT NULL,
                seq INTEGER NOT NULL,
                body TEXT NOT NULL,
                PRIMARY KEY (contact_name, msg_id)
            )
            """
        )
        return conn

    def save_inbound_message(self, contact_name: str, seq: int, body: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO inbound_messages (contact_name, seq, body) VALUES (?, ?, ?)",
                (contact_name, seq, body),
            )
            conn.commit()

    def list_inbound_messages(self, contact_name: str) -> list[tuple[int, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT seq, body FROM inbound_messages WHERE contact_name = ? ORDER BY seq",
                (contact_name,),
            ).fetchall()
        return [(int(seq), str(body)) for seq, body in rows]

    def save_outbound_pending(
        self, contact_name: str, msg_id: str, seq: int, body: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO outbound_pending (contact_name, msg_id, seq, body) VALUES (?, ?, ?, ?)",
                (contact_name, msg_id, seq, body),
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
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT msg_id, seq, body FROM outbound_pending WHERE contact_name = ? ORDER BY seq",
                (contact_name,),
            ).fetchall()
        return [(str(msg_id), int(seq), str(body)) for msg_id, seq, body in rows]

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
