"""Origin parsing and validation.

An origin is scheme://host[:port]. Grants and credentials are matched on exact
origins only: no wildcards, no suffix matching, no implicit subdomains.
"""
from __future__ import annotations

from urllib.parse import urlsplit

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_DEFAULT_PORTS = {"https": 443, "http": 80}


class OriginError(ValueError):
    pass


def normalize_origin(value: str) -> str:
    """Return the canonical origin for a URL or origin string, or raise.

    https is required, except for loopback hosts where http is accepted so the
    broker can be exercised against a local test site.
    """
    if not isinstance(value, str) or not value.strip():
        raise OriginError("empty address")
    value = value.strip()
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in value):
        raise OriginError("address contains whitespace or control characters")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise OriginError(f"cannot parse address: {exc}") from None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("https", "http"):
        raise OriginError("only https addresses are supported")
    if not host:
        raise OriginError("address has no host")
    if parts.username is not None or parts.password is not None:
        raise OriginError("addresses with embedded user info are rejected")
    if "*" in host:
        raise OriginError("wildcards are not supported")
    try:
        host = host.encode("idna").decode("ascii") if not _is_ip(host) else host
    except UnicodeError:
        raise OriginError("invalid host name") from None
    if scheme == "http" and host not in _LOOPBACK:
        raise OriginError("http is only accepted for loopback hosts")
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def origin_of(url: str) -> str | None:
    """Origin of a URL as the browser reports it, or None if it has none we accept."""
    try:
        return normalize_origin(url)
    except OriginError:
        return None


def url_in_origins(url: str, origins: list[str]) -> bool:
    o = origin_of(url)
    return o is not None and o in origins


def _is_ip(host: str) -> bool:
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)
