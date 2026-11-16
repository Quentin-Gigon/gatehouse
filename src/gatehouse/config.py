"""Filesystem layout. Everything lives under one owner-only directory."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    home: Path

    @property
    def vault(self) -> Path:
        return self.home / "vault.json"

    @property
    def db(self) -> Path:
        return self.home / "state.db"

    @property
    def profiles(self) -> Path:
        return self.home / "profiles"

    def ensure(self) -> None:
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.home, 0o700)
        self.profiles.mkdir(mode=0o700, exist_ok=True)


def default_paths() -> Paths:
    return Paths(Path(os.environ.get("GATEHOUSE_HOME", "~/.gatehouse")).expanduser())


DEFAULT_PORT = 8737
