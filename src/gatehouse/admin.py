"""Management operations behind the admin API (used by the Gatehouse app).

Every function here takes the broker's store and unlocked vault and returns plain
data. Nothing returns a password or TOTP secret: unlocking the app lets you change
what agents may do, never read what is in the vault.
"""
from __future__ import annotations

import datetime as dt
import json
import time

from . import importer, totp as totp_mod
from .origins import OriginError, normalize_origin
from .store import Store
from .vault import Vault, new_credential

DURATIONS = ("once", "session", "forever")


class AdminError(ValueError):
    pass


def _origin(url: str) -> str:
    url = url.strip()
    if url and "://" not in url:
        url = "https://" + url
    try:
        return normalize_origin(url)
    except OriginError as e:
        raise AdminError(f"{url or 'address'}: {e}") from None


def _login_url(url: str) -> str:
    url = url.strip()
    return url if "://" in url else "https://" + url


def _totp(secret: str | None):
    if not secret:
        return None
    try:
        return totp_mod.parse_secret(secret.strip())
    except totp_mod.TotpError as e:
        raise AdminError(str(e)) from None


def grant_state(g, boot_id: str) -> str:
    if g["revoked_at"]:
        return "revoked"
    if g["kind"] == "once" and g["used_count"]:
        return "used"
    if g["kind"] == "until" and (g["expires_at"] or 0) <= time.time():
        return "expired"
    if g["kind"] == "session" and g["boot_id"] != boot_id:
        return "ended"
    return "active"


def duration(text: str, boot_id: str) -> dict:
    if text == "once":
        return {"kind": "once"}
    if text == "forever":
        return {"kind": "until_revoked"}
    if text == "session":
        return {"kind": "session", "boot_id": boot_id}
    try:
        d = dt.datetime.fromisoformat(text)
    except ValueError:
        raise AdminError("duration must be once, session, forever, or a date like 2026-12-31") from None
    if d.timestamp() <= time.time():
        raise AdminError("that date is in the past")
    return {"kind": "until", "expires_at": d.timestamp()}


# --- reading ------------------------------------------------------------------------
def overview(store: Store, vault: Vault, key: bytes, boot_id: str, handoffs: list[dict]) -> dict:
    creds = vault.load(key)
    names = {c.id: c.name for c in creds}
    agents = {a["id"]: a["name"] for a in store.agents()}
    return {
        "accounts": [{**c.public(), "login_url": c.login_url, "imported_url": c.imported_url,
                      "pre_click": list(c.pre_click), "success_selector": c.success_selector, "allow_safari": c.allow_safari,
                      "failures": store.failures(c.id), "updated_at": c.updated_at} for c in creds],
        "agents": [{"id": a["id"], "name": a["name"], "created_at": a["created_at"], "revoked_at": a["revoked_at"]}
                   for a in store.agents()],
        "grants": [{"id": g["id"], "agent_id": g["agent_id"], "account_id": g["credential_id"],
                    "origins": json.loads(g["origins"]), "kind": g["kind"], "expires_at": g["expires_at"],
                    "used_count": g["used_count"], "state": grant_state(g, boot_id)} for g in store.grants()],
        "approvals": [{"id": r["id"], "agent_id": r["agent_id"], "agent": agents.get(r["agent_id"], r["agent_id"]),
                       "account_id": r["credential_id"], "account": names.get(r["credential_id"], r["credential_id"]),
                       "origin": r["origin"], "created_at": r["created_at"]} for r in store.approvals()],
        "handoffs": [{**h, "agent": agents.get(h["agent_id"], h["agent_id"]),
                      "account": names.get(h["account_id"], h["account_id"])} for h in handoffs],
        "logins_disabled": store.logins_disabled(),
    }


def activity(store: Store, vault: Vault, key: bytes, limit: int) -> list[dict]:
    names = {c.id: c.name for c in vault.load(key)}
    agents = {a["id"]: a["name"] for a in store.agents()}
    return [{"ts": r["ts"], "action": r["action"], "agent": agents.get(r["agent_id"], r["agent_id"]),
             "account": names.get(r["credential_id"], r["credential_id"]), "origin": r["origin"],
             "decision": r["decision"], "result": r["result"]} for r in store.audit_rows(max(1, min(limit, 1000)))]


# --- accounts -------------------------------------------------------------------------
def add_account(store: Store, vault: Vault, key: bytes, p: dict) -> dict:
    name, username = str(p.get("name") or "").strip(), str(p.get("username") or "").strip()
    password = str(p.get("password") or "")      # passwords keep their spaces
    if not name or not username or not password:
        raise AdminError("name, username and password are required")
    login_url = _login_url(str(p.get("login_url") or ""))
    origins = {_origin(login_url)} | {_origin(str(o)) for o in p.get("extra_websites") or []}
    cred = new_credential(importer.clean(name), username, password, origins=sorted(origins),
                          login_url=login_url, totp=_totp(p.get("totp")),
                          pre_click=[str(s) for s in p.get("pre_click") or [] if s],
                          success_selector=str(p.get("success_selector") or ""))
    with vault.edit(key) as creds:
        creds.append(cred)
    store.audit("account_added", credential_id=cred.id)
    return {"account_id": cred.id}


def edit_account(store: Store, vault: Vault, key: bytes, p: dict) -> dict:
    with vault.edit(key) as creds:
        cr = next((c for c in creds if c.id == p.get("account_id")), None)
        if cr is None:
            raise AdminError("no such account")
        if p.get("name"):
            cr.name = importer.clean(str(p["name"]))
        if p.get("username"):
            cr.username = str(p["username"]).strip()
        if p.get("password"):
            cr.password = str(p["password"])
        if "totp" in p:                              # empty string removes it
            cr.totp = _totp(p["totp"])
        if "websites" in p:
            cr.origins = sorted({_origin(str(o)) for o in p["websites"]})
        if p.get("login_url"):
            cr.login_url = _login_url(str(p["login_url"]))
            cr.origins = sorted(set(cr.origins) | {_origin(cr.login_url)})
        if cr.login_url and _origin(cr.login_url) not in cr.origins:
            raise AdminError("the sign-in page must be on one of the account's websites")
        if "pre_click" in p:
            cr.pre_click = [str(s) for s in p["pre_click"] or [] if s]
        if "success_selector" in p:
            cr.success_selector = str(p["success_selector"] or "")
        if "allow_safari" in p:
            cr.allow_safari = bool(p["allow_safari"])
        cr.updated_at = time.time()
    store.audit("account_edited", credential_id=cr.id)
    return {"account_id": cr.id}


def remove_account(store: Store, vault: Vault, key: bytes, p: dict) -> dict:
    cid = p.get("account_id")
    with vault.edit(key) as creds:
        before = len(creds)
        creds[:] = [c for c in creds if c.id != cid]
        if len(creds) == before:
            raise AdminError("no such account")
    n = store.revoke_grants_for_credential(cid)
    store.audit("account_removed", credential_id=cid, result=f"{n}_grants_revoked")
    return {"grants_revoked": n}


def unblock_account(store: Store, p: dict) -> dict:
    store.clear_failures(str(p.get("account_id")))
    return {}


# --- import -----------------------------------------------------------------------------
def import_preview(p: dict) -> dict:
    try:
        fmt, entries = importer.parse(str(p.get("csv") or ""))
    except importer.ImportError_ as e:
        raise AdminError(str(e)) from None
    return {"format": fmt, "entries": [{k: v for k, v in e.preview().items() if k != "password"} |
                                       {"has_password": bool(e.password)} for e in entries]}


def import_apply(store: Store, vault: Vault, key: bytes, p: dict) -> dict:
    """Import the selected rows. In the app, ticking a row with a website is the approval of that
    website, so (unlike the CLI) its address becomes the account's approved site and sign-in page."""
    try:
        _, entries = importer.parse(str(p.get("csv") or ""))
    except importer.ImportError_ as e:
        raise AdminError(str(e)) from None
    selected = {int(i) for i in p.get("selected") or []}
    choice = str(p.get("on_duplicate") or "skip")
    if choice not in ("skip", "replace", "keep_both"):
        raise AdminError("on_duplicate must be skip, replace or keep_both")
    with vault.edit(key) as creds:
        before = {c.id for c in creds}
        res = importer.apply(entries, selected, creds, lambda e, d: choice)
        if p.get("approve_websites", True):
            for c in creds:
                if c.id not in before and c.imported_url and not c.origins:
                    try:
                        c.origins, c.login_url = [_origin(c.imported_url)], c.imported_url
                    except AdminError:
                        pass
    store.audit("accounts_imported", result=f"{len(res.imported)}_added_{len(res.replaced)}_replaced")
    return {"imported": res.imported, "replaced": res.replaced, "skipped": res.skipped, "notes": res.notes}


# --- agents and access ------------------------------------------------------------------
def connect_agent(store: Store, name: str, port: int) -> dict:
    """Register `name`, or issue new keys if it exists (its grants stay). Returns its config."""
    if not name or len(name) > 40 or not all(ch.isalnum() or ch in "._-" for ch in name):
        raise AdminError("agent name: letters, digits, . _ - (max 40)")
    active = [a for a in store.agents() if a["name"] == name and not a["revoked_at"]]
    if active:
        a = store.rotate_agent(active[0]["id"])
        store.audit("agent_keys_rotated", a["agent_id"])
    else:
        a = store.add_agent(name)
        store.audit("agent_added", a["agent_id"])
    return {"url": f"http://127.0.0.1:{port}", "agent_id": a["agent_id"], "sign_key": a["sign_key"],
            "cdp_endpoint": f"http://127.0.0.1:{port}/cdp/{a['cdp_token']}"}


def revoke_agent(store: Store, p: dict) -> dict:
    ok = store.revoke_agent(str(p.get("agent_id")))
    if ok:
        store.audit("agent_revoked", str(p.get("agent_id")))
    return {"revoked": ok}


def set_access(store: Store, vault: Vault, key: bytes, boot_id: str, p: dict) -> dict:
    """Turn an agent's access to an account on (with a duration) or off (revokes every grant)."""
    agent_id, cid = str(p.get("agent_id")), str(p.get("account_id"))
    agent = store.agent(agent_id)
    if agent is None or agent["revoked_at"]:
        raise AdminError("no such agent")
    cred = vault.get(key, cid)
    if cred is None:
        raise AdminError("no such account")
    for g in store.grants(agent_id=agent_id, credential_id=cid, active_only=True):
        store.revoke_grant(g["id"])
    if not p.get("allowed"):
        store.audit("grant_revoked", agent_id, cid)
        return {"grant_id": None}
    if not cred.origins:
        raise AdminError("this account has no website yet; add one first")
    text = str(p.get("duration") or "forever")
    gid = store.add_grant(agent_id, cid, cred.origins, **duration(text, boot_id))
    store.audit("grant_added", agent_id, cid, ",".join(cred.origins), "allowed", text[:20])
    return {"grant_id": gid}


def approve(store: Store, vault: Vault, key: bytes, boot_id: str, p: dict) -> dict:
    row = next((r for r in store.approvals() if r["id"] == p.get("approval_id")), None)
    if row is None:
        raise AdminError("no pending request with that id")
    with vault.edit(key) as creds:
        cr = next((c for c in creds if c.id == row["credential_id"]), None)
        if cr is None:
            raise AdminError("that account no longer exists")
        if row["origin"] not in cr.origins:
            cr.origins = sorted(set(cr.origins) | {row["origin"]})   # approving the request approves the site
    login_origin = _origin(cr.login_url) if cr.login_url else row["origin"]
    origins = sorted({row["origin"], login_origin} & set(cr.origins))
    gid = store.add_grant(row["agent_id"], cr.id, origins, **duration(str(p.get("duration") or "forever"), boot_id))
    store.resolve_approval(row["id"], "approved")
    store.audit("approval", row["agent_id"], cr.id, row["origin"], "allowed", "approved")
    return {"grant_id": gid}


def deny(store: Store, p: dict) -> dict:
    row = store.resolve_approval(str(p.get("approval_id")), "denied")
    if row:
        store.audit("approval", row["agent_id"], row["credential_id"], row["origin"], "denied", "denied")
    return {"denied": bool(row)}


def set_logins(store: Store, p: dict) -> dict:
    enabled = bool(p.get("enabled"))
    store.set_setting("logins_disabled", "0" if enabled else "1")
    store.audit("logins_enabled" if enabled else "logins_disabled")
    return {"enabled": enabled}
