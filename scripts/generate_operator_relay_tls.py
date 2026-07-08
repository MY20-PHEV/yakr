#!/usr/bin/env python3
"""Generate pairing-anchored TLS material for a relay operator identity.

Writes PEM key/cert under <operator-home>/relay-tls/ and prints the SPKI pin
to embed in delivery profiles (automatic when using relay_descriptor_for_operator).

Example:
  python scripts/generate_operator_relay_tls.py ~/.yakr/charlie
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from yakr_core.identity import Identity
from yakr_core.tls import endpoint_tls_spki_sha256, write_endpoint_tls_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate operator relay TLS PEM files")
    parser.add_argument(
        "operator_home",
        type=Path,
        help="YAKR_HOME directory containing identity.json for the relay operator",
    )
    args = parser.parse_args()
    identity_path = args.operator_home / "identity.json"
    if not identity_path.exists():
        print(f"identity not found: {identity_path}", file=sys.stderr)
        sys.exit(1)

    identity = Identity.load(identity_path)
    tls_dir = args.operator_home / "relay-tls"
    keyfile, certfile = write_endpoint_tls_files(identity, tls_dir)
    spki = endpoint_tls_spki_sha256(identity)
    (tls_dir / "spki_sha256.hex").write_text(spki.hex() + "\n", encoding="utf-8")
    print(f"operator: {identity.name}")
    print(f"tls_key:  {keyfile}")
    print(f"tls_cert: {certfile}")
    print(f"spki_sha256: {spki.hex()}")


if __name__ == "__main__":
    main()
