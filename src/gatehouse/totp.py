"""RFC 6238 TOTP using the standard library's HMAC. No custom cryptography."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, urlsplit


class TotpError(ValueError):
    pass


def parse_secret(value: str) -> dict:
    """Accept a base32 secret or an otpauth://totp/ URI. Returns normalized params."""
    value = value.strip()
    params = {"secret": value, "digits": 6, "period": 30, "algorithm": "SHA1"}
    if value.lower().startswith("otpauth://"):
        parts = urlsplit(value)
        if parts.netloc.lower() != "totp":
            raise TotpError("only otpauth://totp/ URIs are supported")
        q = parse_qs(parts.query)
        if "secret" not in q:
            raise TotpError("otpauth URI has no secret")
        params["secret"] = q["secret"][0]
        params["digits"] = int(q.get("digits", ["6"])[0])
        params["period"] = int(q.get("period", ["30"])[0])
        params["algorithm"] = q.get("algorithm", ["SHA1"])[0].upper()
    params["secret"] = params["secret"].replace(" ", "").replace("-", "").upper()
    if params["algorithm"] not in ("SHA1", "SHA256", "SHA512"):
        raise TotpError("unsupported TOTP algorithm")
    if params["digits"] not in (6, 7, 8) or not 15 <= params["period"] <= 120:
        raise TotpError("unsupported TOTP parameters")
    _decode(params["secret"])
    return params


def _decode(secret: str) -> bytes:
    try:
        return base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    except Exception:
        raise TotpError("TOTP secret is not valid base32") from None


def code(params: dict, at: float | None = None) -> str:
    key = _decode(params["secret"])
    counter = int((time.time() if at is None else at) // params["period"])
    digest = hmac.new(key, struct.pack(">Q", counter), getattr(hashlib, params["algorithm"].lower())).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** params["digits"]).zfill(params["digits"])
