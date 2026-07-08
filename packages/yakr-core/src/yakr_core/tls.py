from __future__ import annotations

import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from yakr_core.identity import Identity

TLS_CERT_DAYS = 825


def ensure_identity_tls_key(identity: Identity) -> ec.EllipticCurvePrivateKey:
    if identity.tls_ecdsa_private is None:
        identity.tls_ecdsa_private = ec.generate_private_key(ec.SECP256R1())
    return identity.tls_ecdsa_private


def spki_sha256_from_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).digest()


def spki_sha256_from_cert_der(cert_der: bytes) -> bytes:
    cert = x509.load_der_x509_certificate(cert_der)
    return spki_sha256_from_public_key(cert.public_key())  # type: ignore[arg-type]


def endpoint_tls_spki_sha256(identity: Identity) -> bytes:
    private_key = ensure_identity_tls_key(identity)
    public_key = private_key.public_key()
    return spki_sha256_from_public_key(public_key)


def build_endpoint_certificate(identity: Identity) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    private_key = ensure_identity_tls_key(identity)
    public_key = private_key.public_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, f"yakr-{identity.name}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yakr"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=TLS_CERT_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName(f"yakr-{identity.name}")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return private_key, cert


def write_endpoint_tls_files(identity: Identity, directory: Path) -> tuple[Path, Path]:
    """Write PEM key + cert for uvicorn / other TLS servers."""
    directory.mkdir(parents=True, exist_ok=True)
    private_key, cert = build_endpoint_certificate(identity)
    key_path = directory / "endpoint.key.pem"
    cert_path = directory / "endpoint.cert.pem"
    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key_path, cert_path


def pinning_ssl_context(expected_spki_sha256: bytes) -> ssl.SSLContext:
    if len(expected_spki_sha256) != 32:
        raise ValueError("expected SPKI pin must be 32 bytes")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    original_wrap = ctx.wrap_socket

    def wrap_with_pin(sock, *args, **kwargs):  # type: ignore[no-untyped-def]
        wrapped = original_wrap(sock, *args, **kwargs)
        cert_der = wrapped.getpeercert(binary_form=True)
        if cert_der is None:
            raise ssl.SSLError("peer did not present a TLS certificate")
        actual = spki_sha256_from_cert_der(cert_der)
        if actual != expected_spki_sha256:
            raise ssl.SSLError("TLS SPKI pin mismatch")
        return wrapped

    ctx.wrap_socket = wrap_with_pin  # type: ignore[method-assign]
    return ctx


def normalize_https_url(url: str) -> str:
    normalized = url.rstrip("/")
    if normalized.startswith("http://"):
        return "https://" + normalized[len("http://") :]
    return normalized


def require_https_url(url: str) -> str:
    normalized = url.rstrip("/")
    if not normalized.startswith("https://"):
        raise ValueError(f"TLS required; URL must use https:// (got {url!r})")
    return normalized
