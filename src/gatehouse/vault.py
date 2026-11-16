"""Encrypted credential vault.

One file, encrypted as a whole with AES-256-GCM. The key is derived from the
master passphrase with scrypt. Both primitives come from the `cryptography`
package; nothing here is home-made. The file is rewritten atomically with
owner-only permissions on every change.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
import secrets
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_AAD = b"gatehouse-vault-v1"
SCRYPT_N = 2 ** 17


class VaultError(Exception):
    pass


class VaultLocked(VaultError):
    pass


class WrongPassphrase(VaultError):
    pass


@dataclass
class Credential:
    id: str
    name: str
    username: str
    password: str
    origins: list[str] = field(default_factory=list)   # approved by the user, never by import
    login_url: str = ""                                 # must sit inside `origins`
    totp: dict | None = None
    imported_url: str = ""                              # informational only
    pre_click: list[str] = field(default_factory=list)  # CSS selectors to click before looking for fields
    success_selector: str = ""                          # CSS selector that only exists when signed in
    created_at: float = 0.0
    updated_at: float = 0.0

    def public(self) -> dict:
        """Metadata that is safe to show to an authorized agent."""
        return {"account_id": self.id, "name": self.name, "username": self.username,
                "origins": list(self.origins), "has_totp": self.totp is not None}


def new_credential(name: str, username: str, password: str, **kw) -> Credential:
    now = time.time()
    return Credential(id=uuid.uuid4().hex[:16], name=name, username=username, password=password,
                      created_at=now, updated_at=now, **kw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _derive(passphrase: str, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=8, p=1).derive(passphrase.encode("utf-8"))


class Vault:
    def __init__(self, path: Path):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, passphrase: str, n: int = SCRYPT_N) -> bytes:
        if self.exists():
            raise VaultError("vault already exists")
        if len(passphrase) < 8:
            raise VaultError("passphrase must be at least 8 characters")
        salt = secrets.token_bytes(16)
        key = _derive(passphrase, salt, n)
        self._write(key, {"credentials": []}, {"name": "scrypt", "n": n, "r": 8, "p": 1, "salt": _b64(salt)})
        return key

    def unlock(self, passphrase: str) -> bytes:
        """Derive the key and prove it by decrypting. Returns the key."""
        kdf = self._header()["kdf"]
        key = _derive(passphrase, base64.b64decode(kdf["salt"]), int(kdf["n"]))
        self.load(key)
        return key

    def load(self, key: bytes) -> list[Credential]:
        doc = self._header()
        try:
            plain = AESGCM(key).decrypt(base64.b64decode(doc["nonce"]), base64.b64decode(doc["ciphertext"]), _AAD)
        except InvalidTag:
            raise WrongPassphrase("wrong passphrase or corrupted vault") from None
        return [Credential(**c) for c in json.loads(plain)["credentials"]]

    def get(self, key: bytes, credential_id: str) -> Credential | None:
        return next((c for c in self.load(key) if c.id == credential_id), None)

    @contextmanager
    def edit(self, key: bytes):
        """Read-modify-write under an exclusive file lock."""
        lock_path = self.path.with_suffix(".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            creds = self.load(key)
            yield creds
            self._write(key, {"credentials": [asdict(c) for c in creds]}, self._header()["kdf"])
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _header(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except FileNotFoundError:
            raise VaultError("vault not initialized; run `gatehouse init`") from None

    def _write(self, key: bytes, data: dict, kdf: dict) -> None:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), _AAD)
        doc = {"version": 1, "kdf": kdf, "cipher": "AES-256-GCM", "nonce": _b64(nonce), "ciphertext": _b64(ct)}
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
