from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from yakr_core.identity import Contact, Identity, export_public_bundle


class LocalStore(Protocol):
    def load_identity(self) -> Identity | None: ...
    def save_identity(self, identity: Identity) -> None: ...
    def get_contact(self, name: str) -> Contact | None: ...
    def save_contact(self, contact: Contact) -> None: ...
    def list_contacts(self) -> list[str]: ...
    def save_inbound_message(self, contact_name: str, seq: int, body: str) -> None: ...
    def list_inbound_messages(self, contact_name: str) -> list[tuple[int, str]]: ...


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
