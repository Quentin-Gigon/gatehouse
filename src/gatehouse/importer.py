"""Selective CSV import.

Importing never approves a website and never creates a grant. The URL found in
an export is kept as a hint (`imported_url`); the user approves origins later.
All imported text is treated as data: it is sanitized for display and never
interpreted.
"""
from __future__ import annotations

import csv
import io
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from . import totp as totp_mod
from .origins import origin_of
from .vault import Credential, new_credential

# canonical field -> accepted header names (lower-case)
_HEADERS = {
    "name": ("name", "title", "account"),
    "url": ("url", "website", "login_uri", "login url", "uri"),
    "username": ("username", "user", "login", "email", "login_username"),
    "password": ("password", "login_password"),
    "totp": ("totp", "otpauth", "otp", "login_totp"),
}
MAX_ROWS = 20000


class ImportError_(ValueError):
    pass


@dataclass
class Entry:
    index: int
    name: str
    url: str
    username: str
    password: str
    totp: str
    unsupported: list[str] = field(default_factory=list)  # column names holding data we do not import
    problems: list[str] = field(default_factory=list)

    def preview(self, reveal: bool = False) -> dict:
        return {"index": self.index, "name": clean(self.name), "username": clean(self.username),
                "url": clean(self.url), "password": self.password if reveal else mask(self.password),
                "totp": "yes" if self.totp else "", "unsupported": self.unsupported, "problems": self.problems}


def clean(text: str, limit: int = 200) -> str:
    """Strip control and formatting characters so imported text cannot drive a terminal."""
    out = "".join(c for c in text if unicodedata.category(c)[0] != "C")
    return out[:limit]


def mask(secret: str) -> str:
    return "" if not secret else "•" * 8


def detect_format(header: list[str]) -> str:
    h = [x.strip().lower() for x in header]
    if h[:4] == ["title", "url", "username", "password"]:
        return "apple"
    return "generic"


def parse(text: str) -> tuple[str, list[Entry]]:
    """Parse a CSV export. Returns (detected format, entries)."""
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    try:
        header = next(reader)
    except StopIteration:
        raise ImportError_("file is empty") from None
    fmt = detect_format(header)
    cols = [h.strip().lower() for h in header]
    mapping: dict[str, int] = {}
    for canon, names in _HEADERS.items():
        for i, c in enumerate(cols):
            if c in names and canon not in mapping:
                mapping[canon] = i
    if "password" not in mapping or "username" not in mapping:
        raise ImportError_("CSV needs at least 'username' and 'password' columns; see docs/IMPORT.md")
    used = set(mapping.values())
    entries: list[Entry] = []
    for n, row in enumerate(reader):
        if n >= MAX_ROWS:
            raise ImportError_("file has too many rows")
        if not any(cell.strip() for cell in row):
            continue

        def get(k: str) -> str:
            i = mapping.get(k)
            return row[i].strip() if i is not None and i < len(row) else ""

        e = Entry(index=len(entries) + 1, name=get("name"), url=get("url"), username=get("username"),
                  password=row[mapping["password"]] if mapping["password"] < len(row) else "", totp=get("totp"))
        e.unsupported = [header[i].strip() for i, cell in enumerate(row)
                         if i not in used and i < len(header) and cell.strip()]
        if not e.password:
            e.problems.append("no password (passkeys and federated logins cannot be imported from CSV)")
        if e.url and origin_of(e.url if "://" in e.url else "https://" + e.url) is None:
            e.problems.append("website address is not a valid https address")
        if e.totp:
            try:
                totp_mod.parse_secret(e.totp)
            except totp_mod.TotpError as exc:
                e.problems.append(f"TOTP ignored: {exc}")
        if not e.name:
            e.name = e.url or e.username
        entries.append(e)
    return fmt, entries


def _host(url: str) -> str:
    o = origin_of(url if "://" in url else "https://" + url) if url else None
    return o or ""


def find_duplicate(entry: Entry, creds: list[Credential]) -> Credential | None:
    for c in creds:
        if c.username != entry.username:
            continue
        hosts = set(c.origins) | ({_host(c.imported_url)} if c.imported_url else set())
        if (_host(entry.url) and _host(entry.url) in hosts) or (not _host(entry.url) and c.name == entry.name):
            return c
    return None


@dataclass
class Result:
    imported: list[str] = field(default_factory=list)
    replaced: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def apply(entries: list[Entry], selected: set[int], creds: list[Credential], on_duplicate) -> Result:
    """Add the selected entries to `creds` in place.

    `on_duplicate(entry, existing)` returns 'skip', 'replace' or 'keep_both'.
    """
    res = Result()
    for e in entries:
        if e.index not in selected:
            continue
        label = clean(e.name)
        if not e.password:
            res.skipped.append(f"{label}: no password")
            continue
        totp = None
        if e.totp:
            try:
                totp = totp_mod.parse_secret(e.totp)
            except totp_mod.TotpError:
                res.notes.append(f"{label}: TOTP secret not imported (invalid)")
        url = e.url if (not e.url or "://" in e.url) else "https://" + e.url
        if url and origin_of(url) is None:
            res.notes.append(f"{label}: website address not kept (invalid)")
            url = ""
        if e.unsupported:
            res.notes.append(f"{label}: not imported: {', '.join(clean(u, 40) for u in e.unsupported)}")
        dup = find_duplicate(e, creds)
        choice = on_duplicate(e, dup) if dup else "keep_both"
        if dup and choice == "skip":
            res.skipped.append(f"{label}: duplicate")
            continue
        if dup and choice == "replace":
            # Secret values are replaced; approved origins and grants stay as the user set them.
            dup.password, dup.totp, dup.imported_url = e.password, totp or dup.totp, url or dup.imported_url
            res.replaced.append(label)
            continue
        creds.append(new_credential(clean(e.name), e.username, e.password, totp=totp, imported_url=url))
        res.imported.append(label)
    return res


def read_file(path: Path) -> str:
    return Path(path).read_text(encoding="utf-8-sig")
