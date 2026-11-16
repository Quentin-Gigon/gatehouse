"""SQLite state: agents, grants, approvals, audit, replay nonces, settings.

No credential values are stored here. Agent request-signing keys are, which is
why the database is owner-only and belongs to the broker's user.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
import uuid
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, sign_key TEXT NOT NULL, cdp_token_hash TEXT NOT NULL,
  created_at REAL NOT NULL, revoked_at REAL);
CREATE TABLE IF NOT EXISTS grants(
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, credential_id TEXT NOT NULL, origins TEXT NOT NULL,
  operation TEXT NOT NULL DEFAULT 'sign_in', kind TEXT NOT NULL, expires_at REAL, boot_id TEXT,
  created_at REAL NOT NULL, revoked_at REAL, used_count INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS approvals(
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, credential_id TEXT NOT NULL, origin TEXT NOT NULL,
  created_at REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
  UNIQUE(agent_id, credential_id, origin, status));
CREATE TABLE IF NOT EXISTS nonces(agent_id TEXT NOT NULL, nonce TEXT NOT NULL, ts REAL NOT NULL,
  PRIMARY KEY(agent_id, nonce));
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, agent_id TEXT, credential_id TEXT,
  origin TEXT, action TEXT NOT NULL, decision TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS failures(credential_id TEXT PRIMARY KEY, count INTEGER NOT NULL, last_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

GRANT_KINDS = ("once", "session", "until", "until_revoked")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: Path):
        new = not Path(path).exists()
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        if new:
            os.chmod(path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(SCHEMA)

    # settings -------------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                        (key, value))

    def logins_disabled(self) -> bool:
        return self.get_setting("logins_disabled", "0") == "1"

    # agents ---------------------------------------------------------------
    def add_agent(self, name: str) -> dict:
        """Create an agent. The returned secrets are shown once and not recoverable."""
        agent_id = "agt_" + uuid.uuid4().hex[:12]
        sign_key = secrets.token_urlsafe(32)
        cdp_token = secrets.token_urlsafe(32)
        self.db.execute("INSERT INTO agents(id,name,sign_key,cdp_token_hash,created_at) VALUES(?,?,?,?,?)",
                        (agent_id, name, sign_key, _hash(cdp_token), time.time()))
        return {"agent_id": agent_id, "sign_key": sign_key, "cdp_token": cdp_token}

    def rotate_agent(self, agent_id: str) -> dict:
        """Issue new keys for an active agent; its grants stay. The old keys stop working at once."""
        sign_key = secrets.token_urlsafe(32)
        cdp_token = secrets.token_urlsafe(32)
        cur = self.db.execute("UPDATE agents SET sign_key=?, cdp_token_hash=? WHERE id=? AND revoked_at IS NULL",
                              (sign_key, _hash(cdp_token), agent_id))
        if cur.rowcount != 1:
            raise KeyError(agent_id)
        return {"agent_id": agent_id, "sign_key": sign_key, "cdp_token": cdp_token}

    def agent(self, agent_id: str):
        return self.db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()

    def agent_by_cdp_token(self, token: str):
        return self.db.execute("SELECT * FROM agents WHERE cdp_token_hash=? AND revoked_at IS NULL",
                               (_hash(token),)).fetchone()

    def agents(self):
        return self.db.execute("SELECT id,name,created_at,revoked_at FROM agents ORDER BY created_at").fetchall()

    def revoke_agent(self, agent_id: str) -> bool:
        cur = self.db.execute("UPDATE agents SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), agent_id))
        return cur.rowcount == 1

    # replay protection ----------------------------------------------------
    def use_nonce(self, agent_id: str, nonce: str, ts: float, window: float) -> bool:
        self.db.execute("DELETE FROM nonces WHERE ts < ?", (time.time() - 2 * window,))
        try:
            self.db.execute("INSERT INTO nonces(agent_id,nonce,ts) VALUES(?,?,?)", (agent_id, nonce, ts))
            return True
        except sqlite3.IntegrityError:
            return False

    # grants ---------------------------------------------------------------
    def add_grant(self, agent_id: str, credential_id: str, origins: list[str], kind: str,
                  expires_at: float | None = None, boot_id: str | None = None) -> str:
        if kind not in GRANT_KINDS:
            raise ValueError("unknown grant duration")
        if kind == "until" and not expires_at:
            raise ValueError("an 'until' grant needs an expiry")
        if kind == "session" and not boot_id:
            raise ValueError("a 'session' grant needs a running broker")
        if not origins:
            raise ValueError("a grant needs at least one origin")
        grant_id = "grt_" + uuid.uuid4().hex[:12]
        self.db.execute("INSERT INTO grants(id,agent_id,credential_id,origins,kind,expires_at,boot_id,created_at)"
                        " VALUES(?,?,?,?,?,?,?,?)",
                        (grant_id, agent_id, credential_id, json.dumps(sorted(set(origins))), kind,
                         expires_at, boot_id, time.time()))
        return grant_id

    def grants(self, agent_id: str | None = None, credential_id: str | None = None, active_only: bool = False):
        q, args = "SELECT * FROM grants WHERE 1=1", []
        if agent_id:
            q += " AND agent_id=?"; args.append(agent_id)
        if credential_id:
            q += " AND credential_id=?"; args.append(credential_id)
        if active_only:
            q += " AND revoked_at IS NULL"
        return self.db.execute(q + " ORDER BY created_at", args).fetchall()

    def revoke_grant(self, grant_id: str) -> bool:
        cur = self.db.execute("UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (time.time(), grant_id))
        return cur.rowcount == 1

    def revoke_grants_for_credential(self, credential_id: str) -> int:
        cur = self.db.execute("UPDATE grants SET revoked_at=? WHERE credential_id=? AND revoked_at IS NULL",
                              (time.time(), credential_id))
        return cur.rowcount

    def consume_once(self, grant_id: str) -> bool:
        """Atomically claim a single-use grant."""
        cur = self.db.execute("UPDATE grants SET used_count=1 WHERE id=? AND kind='once' AND used_count=0 AND revoked_at IS NULL",
                              (grant_id,))
        return cur.rowcount == 1

    def count_use(self, grant_id: str) -> None:
        self.db.execute("UPDATE grants SET used_count=used_count+1 WHERE id=? AND kind!='once'", (grant_id,))

    # approvals ------------------------------------------------------------
    def request_approval(self, agent_id: str, credential_id: str, origin: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO approvals(id,agent_id,credential_id,origin,created_at) VALUES(?,?,?,?,?)",
                        ("apr_" + uuid.uuid4().hex[:12], agent_id, credential_id, origin, time.time()))

    def approvals(self, status: str = "pending"):
        return self.db.execute("SELECT * FROM approvals WHERE status=? ORDER BY created_at", (status,)).fetchall()

    def resolve_approval(self, approval_id: str, status: str):
        row = self.db.execute("SELECT * FROM approvals WHERE id=? AND status='pending'", (approval_id,)).fetchone()
        if row:
            self.db.execute("DELETE FROM approvals WHERE agent_id=? AND credential_id=? AND origin=? AND status=?",
                            (row["agent_id"], row["credential_id"], row["origin"], status))
            self.db.execute("UPDATE approvals SET status=? WHERE id=?", (status, approval_id))
        return row

    # failure throttle -----------------------------------------------------
    def failures(self, credential_id: str) -> int:
        row = self.db.execute("SELECT count FROM failures WHERE credential_id=?", (credential_id,)).fetchone()
        return row["count"] if row else 0

    def record_failure(self, credential_id: str) -> None:
        self.db.execute("INSERT INTO failures(credential_id,count,last_at) VALUES(?,1,?) "
                        "ON CONFLICT(credential_id) DO UPDATE SET count=count+1,last_at=excluded.last_at",
                        (credential_id, time.time()))

    def clear_failures(self, credential_id: str) -> None:
        self.db.execute("DELETE FROM failures WHERE credential_id=?", (credential_id,))

    # audit ----------------------------------------------------------------
    def audit(self, action: str, agent_id: str | None = None, credential_id: str | None = None,
              origin: str | None = None, decision: str | None = None, result: str | None = None) -> None:
        """Only identifiers and fixed status words go in here. Never values."""
        self.db.execute("INSERT INTO audit(ts,agent_id,credential_id,origin,action,decision,result) VALUES(?,?,?,?,?,?,?)",
                        (time.time(), agent_id, credential_id, origin, action, decision, result))

    def audit_rows(self, limit: int = 50):
        return self.db.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def prune_audit(self) -> int:
        days = float(self.get_setting("audit_retention_days", "90"))
        return self.db.execute("DELETE FROM audit WHERE ts < ?", (time.time() - days * 86400,)).rowcount
