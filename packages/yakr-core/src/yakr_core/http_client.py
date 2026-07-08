from __future__ import annotations

import os
import ssl
from typing import Any
from urllib.parse import urlparse

import httpx

from yakr_core.identity import Contact, Identity
from yakr_core.store import FileLocalStore
from yakr_core.tls import pinning_ssl_context, require_https_url


def endpoint_base_url(url: str) -> str:
    """Normalize to scheme://host:port without path (for TLS pin lookup)."""
    parsed = urlparse(url.rstrip("/"))
    if not parsed.scheme or not parsed.hostname:
        return url.rstrip("/")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{parsed.scheme}://{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}"


def _pin_from_profile_relay_descriptors(profile: DeliveryProfile, normalized: str) -> bytes | None:
    for descriptor in profile.relay_descriptors:
        if endpoint_base_url(descriptor.url) == normalized and descriptor.tls_spki_sha256:
            return descriptor.tls_spki_sha256
    return None


def relay_tls_pins_from_store(store: FileLocalStore | None) -> dict[str, bytes]:
    """Map relay base URL -> TLS pin from any signed profile stored locally."""
    if store is None:
        return {}
    pins: dict[str, bytes] = {}
    local = store.load_local_profile()
    if local is not None:
        for descriptor in local.relay_descriptors:
            if descriptor.tls_spki_sha256:
                pins[endpoint_base_url(descriptor.url)] = descriptor.tls_spki_sha256
    for name in store.list_contacts():
        contact = store.get_contact(name)
        if contact is None or contact.delivery_profile is None:
            continue
        for descriptor in contact.delivery_profile.relay_descriptors:
            if descriptor.tls_spki_sha256:
                pins[endpoint_base_url(descriptor.url)] = descriptor.tls_spki_sha256
    return pins


def operator_tls_pins(store: FileLocalStore | None) -> dict[str, bytes]:
    """Map operator name -> SPKI SHA-256 from known signed delivery profiles."""
    if store is None:
        return {}
    pins: dict[str, bytes] = {}
    identity = store.load_identity()
    if identity is not None:
        local = store.load_local_profile()
        if local is not None and local.endpoint_tls_spki_sha256:
            pins[identity.name] = local.endpoint_tls_spki_sha256
    for name in store.list_contacts():
        contact = store.get_contact(name)
        if contact is None or contact.delivery_profile is None:
            continue
        spki = contact.delivery_profile.endpoint_tls_spki_sha256
        if spki:
            pins[name] = spki
    return pins


def url_operator_map(store: FileLocalStore | None) -> dict[str, str]:
    """Map normalized relay/direct URL -> operator name."""
    if store is None:
        return {}
    mapping: dict[str, str] = {}
    local = store.load_local_profile()
    if local is not None:
        for descriptor in local.relay_descriptors:
            mapping[endpoint_base_url(descriptor.url)] = descriptor.name
        for hint in local.direct_hints:
            if identity := store.load_identity():
                mapping[endpoint_base_url(hint)] = identity.name
    for name in store.list_contacts():
        contact = store.get_contact(name)
        if contact is None or contact.delivery_profile is None:
            continue
        profile = contact.delivery_profile
        for descriptor in profile.relay_descriptors:
            mapping[endpoint_base_url(descriptor.url)] = descriptor.name
        for hint in profile.direct_hints:
            mapping[endpoint_base_url(hint)] = contact.name
    return mapping


def resolve_tls_pin_for_url(
    url: str,
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    explicit_pin: bytes | None = None,
    extra_pins_by_url: dict[str, bytes] | None = None,
) -> bytes | None:
    if explicit_pin is not None:
        return explicit_pin
    normalized = endpoint_base_url(url)
    if extra_pins_by_url:
        for candidate, pin in extra_pins_by_url.items():
            if endpoint_base_url(candidate) == normalized:
                return pin
    if contact is not None and contact.delivery_profile is not None:
        pin = _pin_from_profile_relay_descriptors(contact.delivery_profile, normalized)
        if pin is not None:
            return pin
    pin = relay_tls_pins_from_store(store).get(normalized)
    if pin is not None:
        return pin
    operators = operator_tls_pins(store)
    if contact is not None and contact.delivery_profile is not None:
        profile = contact.delivery_profile
        for descriptor in profile.relay_descriptors:
            if endpoint_base_url(descriptor.url) == normalized:
                if descriptor.name in operators:
                    return operators[descriptor.name]
                if descriptor.name == contact.name and profile.endpoint_tls_spki_sha256:
                    return profile.endpoint_tls_spki_sha256
        for hint in profile.direct_hints:
            if endpoint_base_url(hint) == normalized and profile.endpoint_tls_spki_sha256:
                return profile.endpoint_tls_spki_sha256
    url_ops = url_operator_map(store)
    operator = url_ops.get(normalized)
    if operator is not None and operator in operators:
        return operators[operator]
    return None


def tls_required() -> bool:
    return os.environ.get("YAKR_REQUIRE_TLS", "1").lower() not in {"0", "false", "no"}


def verify_param_for_url(
    url: str,
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    identity: Identity | None = None,
    explicit_pin: bytes | None = None,
    extra_pins_by_url: dict[str, bytes] | None = None,
) -> bool | ssl.SSLContext:
    normalized = url.rstrip("/")
    if normalized.startswith("http://"):
        if tls_required():
            raise ValueError(f"plain HTTP disabled (YAKR_REQUIRE_TLS): {url}")
        return True
    if not normalized.startswith("https://"):
        return True
    pin = resolve_tls_pin_for_url(
        normalized,
        store=store,
        contact=contact,
        explicit_pin=explicit_pin,
        extra_pins_by_url=extra_pins_by_url,
    )
    if pin is None:
        if os.environ.get("YAKR_TLS_INSECURE", "").lower() in {"1", "true", "yes"}:
            return False
        raise ValueError(f"no TLS SPKI pin for {url}")
    return pinning_ssl_context(pin)


def yakr_request(
    method: str,
    url: str,
    *,
    store: FileLocalStore | None = None,
    contact: Contact | None = None,
    identity: Identity | None = None,
    explicit_pin: bytes | None = None,
    extra_pins_by_url: dict[str, bytes] | None = None,
    timeout: float = 10.0,
    **kwargs: Any,
) -> httpx.Response:
    if tls_required() and url.startswith("http://"):
        url = require_https_url(url)
    verify = verify_param_for_url(
        url,
        store=store,
        contact=contact,
        identity=identity,
        explicit_pin=explicit_pin,
        extra_pins_by_url=extra_pins_by_url,
    )
    return httpx.request(method, url, verify=verify, timeout=timeout, **kwargs)


def yakr_get(url: str, **kwargs: Any) -> httpx.Response:
    return yakr_request("GET", url, **kwargs)


def yakr_post(url: str, **kwargs: Any) -> httpx.Response:
    return yakr_request("POST", url, **kwargs)
