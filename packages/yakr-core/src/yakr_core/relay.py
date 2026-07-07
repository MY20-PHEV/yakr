from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

RelayRole = Literal["entry", "mailbox", "both"]


@dataclass(frozen=True)
class RelayNode:
    name: str
    role: RelayRole
    url: str
    wrap_secret: bytes

    @classmethod
    def from_dict(cls, name: str, payload: dict[str, str]) -> RelayNode:
        return cls(
            name=name,
            role=payload["role"],  # type: ignore[arg-type]
            url=payload["url"].rstrip("/"),
            wrap_secret=_db64(payload["wrap_secret"]),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "role": self.role,
            "url": self.url,
            "wrap_secret": _b64(self.wrap_secret),
        }


def load_relay_network(path: Path) -> dict[str, RelayNode]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return {name: RelayNode.from_dict(name, data) for name, data in raw.items()}


def save_relay_network(path: Path, nodes: dict[str, RelayNode]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {name: node.to_dict() for name, node in nodes.items()}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _db64(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
