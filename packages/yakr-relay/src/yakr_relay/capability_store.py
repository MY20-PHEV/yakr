"""Registered relay capability grants."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from yakr_core.capability_grant import CapabilityGrant, verify_capability_grant
from yakr_relay.store import _b64decode, _b64encode

DEFAULT_CAPABILITY_OVERLAP_MS = 48 * 60 * 60 * 1000


@dataclass
class CapabilityGrantStore:
    """In-memory grant registry with optional JSON persistence."""

    root: Path
    overlap_window_ms: int = DEFAULT_CAPABILITY_OVERLAP_MS

    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self._path = self.root / "capability_grants.json"
        self._active: dict[str, dict] = {}
        self._seen_nonces: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        payload = json.loads(self._path.read_text(encoding="utf-8"))
        self._active = dict(payload.get("active", {}))
        self._seen_nonces = dict(payload.get("seen_nonces", {}))
        overlap = payload.get("overlap_window_ms")
        if overlap is not None:
            self.overlap_window_ms = int(overlap)

    def _save(self) -> None:
        self._path.write_text(
            json.dumps(
                {
                    "active": self._active,
                    "seen_nonces": self._seen_nonces,
                    "overlap_window_ms": self.overlap_window_ms,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    def _prune_nonces(self, *, now_ms: int | None = None) -> None:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        ttl = 10 * 60 * 1000
        self._seen_nonces = {
            key: seen_at for key, seen_at in self._seen_nonces.items() if now - seen_at <= ttl
        }

    def register(
        self,
        grant: CapabilityGrant,
        *,
        relay_signing_public: bytes,
        relay_name: str,
        relay_tls_spki_sha256: bytes,
    ) -> None:
        verify_capability_grant(
            grant,
            relay_signing_public=relay_signing_public,
            relay_name=relay_name,
            relay_tls_spki_sha256=relay_tls_spki_sha256,
        )
        key = _b64encode(grant.capability_id)
        existing = self._active.get(key)
        if existing is not None:
            prev = CapabilityGrant.from_bytes(_b64decode(existing["grant_b64"]))
            if grant.capability_generation < prev.capability_generation:
                raise ValueError("capability generation rollback rejected")
        self._active[key] = {
            "grant_b64": grant.to_b64(),
            "registered_at": int(time.time() * 1000),
            "revoked_at": None,
            "overlap_until_ms": None,
        }
        self._save()

    def revoke_with_overlap(
        self,
        capability_id: bytes,
        *,
        now_ms: int | None = None,
        overlap_window_ms: int | None = None,
    ) -> None:
        """Begin overlap teardown for a superseded capability id."""
        now = int(time.time() * 1000) if now_ms is None else now_ms
        window = self.overlap_window_ms if overlap_window_ms is None else overlap_window_ms
        key = _b64encode(capability_id)
        record = self._active.get(key)
        if record is None:
            return
        record["revoked_at"] = now
        record["overlap_until_ms"] = now + window
        self._save()

    def revoke_immediately(
        self,
        capability_id: bytes,
        *,
        now_ms: int | None = None,
    ) -> None:
        """Revoke a capability id with zero overlap."""
        now = int(time.time() * 1000) if now_ms is None else now_ms
        self.revoke_with_overlap(capability_id, now_ms=now, overlap_window_ms=0)

    def is_registered(self, grant: CapabilityGrant, *, now_ms: int | None = None) -> bool:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        key = _b64encode(grant.capability_id)
        record = self._active.get(key)
        if record is None:
            return False
        stored = CapabilityGrant.from_bytes(_b64decode(record["grant_b64"]))
        if stored.capability_generation != grant.capability_generation:
            return False
        overlap_until = record.get("overlap_until_ms")
        if overlap_until is not None and now >= int(overlap_until):
            return False
        return True

    def consume_nonce(self, nonce_b64: str, *, now_ms: int | None = None) -> None:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        self._prune_nonces(now_ms=now)
        if nonce_b64 in self._seen_nonces:
            raise ValueError("capability nonce replay")
        self._seen_nonces[nonce_b64] = now
        self._save()
