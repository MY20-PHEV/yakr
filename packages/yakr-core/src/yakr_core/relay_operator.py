"""Dedicated relay operator identity bundled for homelab/VPS deploy."""

from __future__ import annotations

import json
import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from yakr_core.delivery_profile import (
    DeliveryProfile,
    RelayDescriptor,
    create_delivery_profile,
    relay_descriptor_for_operator,
)
from yakr_core.identity import Contact, Identity, export_public_bundle, b64encode, b64decode
from yakr_core.profile_ack import apply_peer_profile_ack
from yakr_core.store import FileLocalStore
from yakr_core.tls import endpoint_tls_spki_sha256, write_endpoint_tls_files


MANIFEST_VERSION = 1


@dataclass(frozen=True)
class RelayOperatorManifest:
    version: int
    operator_name: str
    owner_name: str
    public_url: str
    host_port: int
    wrap_secret: bytes
    operator_home: str
    created_at: int

    def to_dict(self) -> dict[str, str | int]:
        return {
            "version": self.version,
            "operator_name": self.operator_name,
            "owner_name": self.owner_name,
            "public_url": self.public_url,
            "host_port": self.host_port,
            "wrap_secret": b64encode(self.wrap_secret),
            "operator_home": self.operator_home,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str | int]) -> RelayOperatorManifest:
        return cls(
            version=int(payload["version"]),
            operator_name=str(payload["operator_name"]),
            owner_name=str(payload["owner_name"]),
            public_url=str(payload["public_url"]).rstrip("/"),
            host_port=int(payload["host_port"]),
            wrap_secret=b64decode(str(payload["wrap_secret"])),
            operator_home=str(payload["operator_home"]),
            created_at=int(payload["created_at"]),
        )


@dataclass(frozen=True)
class RelayOperatorBundle:
    manifest: RelayOperatorManifest
    operator_store: FileLocalStore
    descriptor: RelayDescriptor
    owner_contact: Contact

    @property
    def operator_home(self) -> Path:
        return self.operator_store.root


def relay_operator_home(owner_root: Path, operator_name: str) -> Path:
    return owner_root / "relays" / operator_name


def manifest_path(operator_home: Path) -> Path:
    return operator_home / "manifest.json"


def load_relay_operator_manifest(operator_home: Path) -> RelayOperatorManifest:
    path = manifest_path(operator_home)
    if not path.exists():
        raise FileNotFoundError(f"relay operator manifest not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return RelayOperatorManifest.from_dict(payload)


def _owner_local_profile(owner_store: FileLocalStore, owner: Identity) -> DeliveryProfile:
    profile = owner_store.load_local_profile()
    if profile is not None:
        return profile
    return create_delivery_profile(owner, relay_descriptors=[])


def _write_relay_env(operator_home: Path, manifest: RelayOperatorManifest) -> Path:
    env_path = operator_home / "relay.env"
    lines = [
        f"RELAY_NAME={manifest.operator_name}",
        f"YAKR_RELAY_NAME={manifest.operator_name}",
        f"PUBLIC_URL={manifest.public_url}",
        f"HOST_PORT={manifest.host_port}",
        f"WRAP_SECRET={b64encode(manifest.wrap_secret)}",
        f"OWNER_NAME={manifest.owner_name}",
    ]
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return env_path


def _write_deploy_compose(operator_home: Path, manifest: RelayOperatorManifest) -> Path:
    deploy_dir = operator_home / "deploy"
    deploy_dir.mkdir(parents=True, exist_ok=True)
    compose_path = deploy_dir / "docker-compose.yml"
    compose_path.write_text(
        f"""services:
  relay:
    image: yakr-relay:local
    container_name: yakr-{manifest.operator_name}
    restart: unless-stopped
    ports:
      - "{manifest.host_port}:8080"
    volumes:
      - {manifest.operator_name}-data:/data
      - ../relay-tls:/tls:ro
    command:
      - yakr-relay
      - serve
      - --host=0.0.0.0
      - --port=8080
      - --data-dir=/data
      - --role=both
      - --name={manifest.operator_name}
      - --wrap-secret={b64encode(manifest.wrap_secret)}
      - --ssl-keyfile=/tls/endpoint.key.pem
      - --ssl-certfile=/tls/endpoint.cert.pem

volumes:
  {manifest.operator_name}-data:
""",
        encoding="utf-8",
    )
    deploy_env = deploy_dir / "deploy.env"
    deploy_env.write_text(
        "\n".join(
            [
                f"VPS_HOST=",
                f"CHARLIE_PORT={manifest.host_port}",
                f"CHARLIE_WRAP_SECRET={b64encode(manifest.wrap_secret)}",
                f"CHARLIE_TLS_DIR={operator_home / 'relay-tls'}",
                f"RELAY_NAME={manifest.operator_name}",
                f"RELAY_CONTAINER=yakr-{manifest.operator_name}",
                f"RELAY_DATA_VOLUME=yakr-{manifest.operator_name}-data",
                f"URL_EXPORT_NAME={manifest.operator_name.upper().replace('-', '_')}_URL",
                f"PUBLIC_URL={manifest.public_url}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return compose_path


def create_relay_operator(
    owner_store: FileLocalStore,
    *,
    operator_name: str,
    public_url: str,
    host_port: int = 8090,
    force: bool = False,
) -> RelayOperatorBundle:
    """Create a dedicated relay operator identity pre-paired with the owner."""
    owner = owner_store.load_identity()
    if owner is None:
        raise ValueError("owner identity not initialized")

    if operator_name == owner.name:
        raise ValueError(
            "operator name must differ from owner identity name; "
            "use `yakr relay embed` for same-name embedded relay"
        )

    if owner_store.get_contact(operator_name) is not None and not force:
        raise ValueError(f"contact {operator_name!r} already exists; use --force to recreate bundle")

    operator_home = relay_operator_home(owner_store.root, operator_name)
    if operator_home.exists():
        if not force:
            raise FileExistsError(f"relay operator home already exists: {operator_home}")
        shutil.rmtree(operator_home)

    operator_home.mkdir(parents=True, exist_ok=True)
    operator_store = FileLocalStore(operator_home)

    operator = Identity.generate(operator_name)
    operator_store.save_identity(operator)

    wrap_secret = secrets.token_bytes(32)
    write_endpoint_tls_files(operator, operator_home / "relay-tls")
    spki_path = operator_home / "relay-tls" / "spki_sha256.hex"
    spki_path.write_text(endpoint_tls_spki_sha256(operator).hex() + "\n", encoding="utf-8")

    public_url = public_url.rstrip("/")
    descriptor = relay_descriptor_for_operator(
        operator,
        "both",
        public_url,
        wrap_secret,
    )
    operator_profile = create_delivery_profile(
        operator,
        relay_descriptors=[descriptor],
    )
    operator_store.save_local_profile(operator_profile)

    owner_profile = _owner_local_profile(owner_store, owner)

    owner_operator = Contact.establish(owner, operator_name, export_public_bundle(operator))
    owner_operator.delivery_profile = operator_profile
    apply_peer_profile_ack(owner_operator, operator_profile)
    owner_store.save_contact(owner_operator)

    operator_owner = Contact.establish(operator, owner.name, export_public_bundle(owner))
    operator_owner.delivery_profile = owner_profile
    apply_peer_profile_ack(operator_owner, owner_profile)
    operator_store.save_contact(operator_owner)

    manifest = RelayOperatorManifest(
        version=MANIFEST_VERSION,
        operator_name=operator_name,
        owner_name=owner.name,
        public_url=public_url,
        host_port=host_port,
        wrap_secret=wrap_secret,
        operator_home=f"relays/{operator_name}",
        created_at=int(time.time() * 1000),
    )
    manifest_path(operator_home).write_text(
        json.dumps(manifest.to_dict(), indent=2),
        encoding="utf-8",
    )
    _write_relay_env(operator_home, manifest)
    _write_deploy_compose(operator_home, manifest)

    return RelayOperatorBundle(
        manifest=manifest,
        operator_store=operator_store,
        descriptor=descriptor,
        owner_contact=owner_operator,
    )
