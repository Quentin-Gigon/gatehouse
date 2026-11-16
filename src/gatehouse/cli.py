"""Local management interface. Run it as the user that owns the broker's data.

Secrets are only ever read from a hidden prompt or a file, never from command
arguments (which other processes can see) and never echoed.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import getpass
import json
import os
import signal
import stat
import sys
import time
from pathlib import Path

from . import importer, totp as totp_mod
from .config import DEFAULT_PORT, Paths, default_paths
from .origins import OriginError, normalize_origin
from .store import Store
from .vault import Vault, VaultError, new_credential


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def ask(prompt: str, default: str = "") -> str:
    val = input(f"{prompt}{f' [{default}]' if default else ''}: ").strip()
    return val or default


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")


def read_passphrase(args, prompt: str = "Vault passphrase: ") -> str:
    path = getattr(args, "passphrase_file", None) or os.environ.get("GATEHOUSE_PASSPHRASE_FILE")
    if path:
        st = os.stat(path)
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            die("passphrase file must be readable by its owner only (chmod 600)")
        return Path(path).read_text().rstrip("\n")
    return getpass.getpass(prompt)


def when(ts) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M") if ts else "-"


class Ctx:
    def __init__(self, args):
        self.args = args
        self.paths: Paths = default_paths()
        self._key = None

    @property
    def store(self) -> Store:
        if not self.paths.db.exists() and not self.paths.vault.exists():
            die("not initialized; run `gatehouse init`")
        return Store(self.paths.db)

    @property
    def vault(self) -> Vault:
        return Vault(self.paths.vault)

    @property
    def key(self) -> bytes:
        if self._key is None:
            try:
                self._key = self.vault.unlock(read_passphrase(self.args))
            except VaultError as e:
                die(str(e))
        return self._key

    def cred(self, ref: str):
        matches = [c for c in self.vault.load(self.key) if c.id == ref or c.name.lower() == ref.lower()]
        if len(matches) != 1:
            die(f"no single account matches {ref!r}; use the id from `gatehouse account list`")
        return matches[0]

    def agent_id(self, ref: str) -> str:
        agents = self.store.agents()
        matches = [a for a in agents if a["id"] == ref or (a["name"] == ref and not a["revoked_at"])] or \
                  [a for a in agents if a["name"] == ref]
        if len(matches) != 1:
            die(f"no single agent matches {ref!r}")
        return matches[0]["id"]


# --- init / serve -------------------------------------------------------------
def cmd_init(c: Ctx) -> None:
    c.paths.ensure()
    if c.vault.exists():
        die("already initialized")
    p1 = read_passphrase(c.args, "Choose a vault passphrase (min 8 characters): ")
    from_file = getattr(c.args, "passphrase_file", None) or os.environ.get("GATEHOUSE_PASSPHRASE_FILE")
    if not from_file and p1 != getpass.getpass("Repeat: "):
        die("passphrases differ")
    try:
        c.vault.create(p1)
    except VaultError as e:
        die(str(e))
    Store(c.paths.db)
    print(f"Initialized {c.paths.home}. There is no passphrase recovery: back up the passphrase and vault.json together.")


def cmd_serve(c: Ctx) -> None:
    from . import login as L
    from .server import Broker, serve
    c.paths.ensure()
    key = None if c.args.locked else c.key
    broker = Broker(c.paths, key, c.args.port, headless=c.args.headless, chrome=c.args.chrome,
                    chrome_args=tuple(c.args.chrome_arg or ()), timeouts=L.Timeouts(human=c.args.human_timeout))

    async def main():
        runner = await serve(broker)
        print(f"gatehouse listening on 127.0.0.1:{c.args.port} ({'locked' if key is None else 'unlocked'}). Ctrl-C to stop.")
        stop = asyncio.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        try:
            await stop.wait()
        finally:
            await runner.cleanup()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


def cmd_selftest(c: Ctx) -> None:
    """Ask the running broker for a browser through a throwaway agent, so a broken install shows now
    and not on an agent's first sign-in."""
    from .client import BrokerClient
    s = c.store
    if not s.get_setting("boot_id"):
        die("the broker is not running")
    a = s.add_agent("selftest")
    try:
        client = BrokerClient(f"http://127.0.0.1:{s.get_setting('port', str(DEFAULT_PORT))}", a["agent_id"], a["sign_key"])
        try:
            _, acc = client.call("/v1/accounts")
            _, br = client.call("/v1/browser")
        except OSError as e:
            die(f"broker unreachable: {e}")
        print(f"broker:  running")
        print(f"vault:   {'unlocked' if acc.get('status') == 'ok' else acc.get('status')}")
        print(f"browser: {'starts' if br.get('status') == 'ok' else br.get('status')}")
        if acc.get("status") != "ok" or br.get("status") != "ok":
            raise SystemExit(1)
    finally:
        s.revoke_agent(a["agent_id"])


def cmd_admin_token(c: Ctx) -> None:
    """For the Gatehouse app: a token for the running broker's admin API. Running this needs the
    broker user's rights, which is what makes the app ask for your Mac password to unlock."""
    print(c.store.add_admin_token(c.args.max_age))


def cmd_status(c: Ctx) -> None:
    s = c.store
    print(f"home:            {c.paths.home}")
    print(f"broker running:  {'yes, port ' + s.get_setting('port', '?') if s.get_setting('boot_id') else 'no'}")
    print(f"new logins:      {'DISABLED' if s.logins_disabled() else 'enabled'}")
    print(f"agents:          {sum(1 for a in s.agents() if not a['revoked_at'])}")
    print(f"active grants:   {len(s.grants(active_only=True))}")
    print(f"pending approvals: {len(s.approvals())}")


# --- accounts -------------------------------------------------------------------
def _ask_origin(prompt: str) -> str:
    while True:
        try:
            return normalize_origin(ask(prompt))
        except OriginError as e:
            print(f"  not accepted: {e}")


def cmd_account_add(c: Ctx) -> None:
    key = c.key
    name = ask("Friendly name")
    username = ask("Username or email")
    password = getpass.getpass("Password (hidden): ")
    if not name or not username or not password:
        die("name, username and password are required")
    login_url = ask("Sign-in page address (https://...)")
    try:
        origin = normalize_origin(login_url)
    except OriginError as e:
        die(f"sign-in address not accepted: {e}")
    origins = [origin]
    print(f"Approved website: {origin}")
    while confirm("Approve another website for this account (e.g. a separate auth domain)?"):
        origins.append(_ask_origin("Website"))
    secret = getpass.getpass("TOTP secret or otpauth:// URI (hidden, empty to skip): ").strip()
    try:
        totp = totp_mod.parse_secret(secret) if secret else None
    except totp_mod.TotpError as e:
        die(str(e))
    cred = new_credential(importer.clean(name), username, password, origins=sorted(set(origins)),
                          login_url=login_url, totp=totp)
    with c.vault.edit(key) as creds:
        creds.append(cred)
    print(f"Added account {cred.id}. No agent can use it until you add a grant.")


def cmd_account_list(c: Ctx) -> None:
    s = c.store
    for cr in c.vault.load(c.key):
        grants = len(s.grants(credential_id=cr.id, active_only=True))
        flags = ("" if cr.origins else "  [no approved website yet]") + (f"  [blocked: {s.failures(cr.id)} failed logins]" if s.failures(cr.id) >= 2 else "")
        print(f"{cr.id}  {cr.name}  <{cr.username}>  {', '.join(cr.origins) or cr.imported_url or '-'}"
              f"  totp={'yes' if cr.totp else 'no'}  grants={grants}{flags}")


def cmd_account_edit(c: Ctx) -> None:
    cr0 = c.cred(c.args.account)
    a = c.args
    with c.vault.edit(c.key) as creds:
        cr = next(x for x in creds if x.id == cr0.id)
        if a.name:
            cr.name = importer.clean(a.name)
        if a.username:
            cr.username = a.username
        if a.password:
            cr.password = getpass.getpass("New password (hidden): ")
        if a.totp:
            secret = getpass.getpass("TOTP secret or otpauth:// URI (hidden, empty to remove): ").strip()
            cr.totp = totp_mod.parse_secret(secret) if secret else None
        for o in a.approve_origin or []:
            cr.origins = sorted(set(cr.origins) | {normalize_origin(o)})
        for o in a.remove_origin or []:
            cr.origins = [x for x in cr.origins if x != normalize_origin(o)]
        if a.login_url:
            if normalize_origin(a.login_url) not in cr.origins:
                die("the sign-in address must be on an approved website; add it with --approve-origin first")
            cr.login_url = a.login_url
        if a.pre_click is not None:
            cr.pre_click = [s for s in a.pre_click if s]
        if a.success_selector is not None:
            cr.success_selector = a.success_selector
        cr.updated_at = time.time()
    print("Updated.")


def cmd_account_remove(c: Ctx) -> None:
    cr = c.cred(c.args.account)
    if not confirm(f"Remove account {cr.name!r} and revoke its grants?"):
        return
    with c.vault.edit(c.key) as creds:
        creds[:] = [x for x in creds if x.id != cr.id]
    n = c.store.revoke_grants_for_credential(cr.id)
    print(f"Removed. {n} grant(s) revoked. Website sessions already open in agent browsers are not ended by this.")


def cmd_account_unblock(c: Ctx) -> None:
    c.store.clear_failures(c.cred(c.args.account).id)
    print("Failure counter reset.")


# --- import -------------------------------------------------------------------------
def _parse_selection(text: str, n: int) -> set[int]:
    out: set[int] = set()
    for part in text.replace(" ", "").split(","):
        if not part:
            continue
        lo, _, hi = part.partition("-")
        out.update(range(int(lo), int(hi or lo) + 1))
    return {i for i in out if 1 <= i <= n}


def cmd_import(c: Ctx) -> None:
    path = Path(c.args.file)
    print("Note: a CSV export contains your passwords in plain text. Keep it off shared and synced folders.")
    try:
        fmt, entries = importer.parse(importer.read_file(path))
    except (importer.ImportError_, OSError, UnicodeError) as e:
        die(str(e))
    print(f"Format: {fmt}. {len(entries)} entries. Nothing is imported until you select it.\n")
    for e in entries:
        p = e.preview()
        extra = "".join(f"  ! {x}" for x in p["problems"])
        print(f"{p['index']:>4}  {p['name'][:32]:<32}  {p['username'][:30]:<30}  {p['password']:<8}  {p['url'][:40]}{extra}")
    try:
        selected = _parse_selection(ask("\nEntries to import (e.g. 2,5-7; empty for none)"), len(entries))
    except ValueError:
        die("could not read the selection")
    if not selected:
        print("Nothing imported.")
        return
    key = c.key

    def on_dup(entry, existing) -> str:
        ans = ask(f"'{importer.clean(entry.name)}' looks like existing account '{existing.name}': [s]kip, [r]eplace, [k]eep both", "s")
        return {"r": "replace", "k": "keep_both"}.get(ans[:1].lower(), "skip")

    with c.vault.edit(key) as creds:
        res = importer.apply(entries, selected, creds, on_dup)
    print(f"\nImported {len(res.imported)}, replaced {len(res.replaced)}, skipped {len(res.skipped)}.")
    for line in res.skipped + res.notes:
        print(f"  - {line}")
    print("Imported accounts have no approved website and no grants. Approve one with:\n"
          "  gatehouse account edit <id> --approve-origin https://... --login-url https://...")
    if not c.args.keep_file and confirm(f"Delete the export file {path} now?"):
        path.unlink()
        print("Deleted. On SSDs and synced folders this is not a secure erase; older copies may persist.")


# --- agents ------------------------------------------------------------------------
def cmd_agent_add(c: Ctx) -> None:
    s = c.store
    if any(a["name"] == c.args.name and not a["revoked_at"] for a in s.agents()):
        die(f"an active agent named {c.args.name!r} exists; use `agent rotate` for new keys or `agent revoke` first")
    _issue_agent_keys(c, s.add_agent(c.args.name))


def cmd_agent_rotate(c: Ctx) -> None:
    a = c.store.rotate_agent(c.agent_id(c.args.agent))
    c.store.audit("agent_keys_rotated", a["agent_id"])
    _issue_agent_keys(c, a)


def _issue_agent_keys(c: Ctx, a: dict) -> None:
    s = c.store
    port = s.get_setting("port", str(DEFAULT_PORT))
    cfg = {"url": f"http://127.0.0.1:{port}", "agent_id": a["agent_id"], "sign_key": a["sign_key"]}
    endpoint = f"http://127.0.0.1:{port}/cdp/{a['cdp_token']}"
    if c.args.write_config == "-":
        # Machine-readable, for a setup script running as the agent's user to store itself.
        print(json.dumps({**cfg, "cdp_endpoint": endpoint}))
        return
    out = Path(c.args.write_config).expanduser()
    fd = os.open(out, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(cfg, f)
    print(f"Agent {a['agent_id']} keys issued.")
    print(f"  API config for the MCP adapter written to {out} (owner-only).")
    print(f"  Browser endpoint for the agent's browser tool (shown once):\n    {endpoint}")
    print("Whoever holds these can act as this agent. They grant nothing until you add a grant.")


def cmd_agent_list(c: Ctx) -> None:
    for a in c.store.agents():
        print(f"{a['id']}  {a['name']}  created {when(a['created_at'])}  {'REVOKED ' + when(a['revoked_at']) if a['revoked_at'] else 'active'}")


def cmd_agent_revoke(c: Ctx) -> None:
    print("Revoked." if c.store.revoke_agent(c.agent_id(c.args.agent)) else "Already revoked.")


# --- grants ------------------------------------------------------------------------
def _duration(c: Ctx, text: str) -> dict:
    if text == "once":
        return {"kind": "once"}
    if text == "forever":
        return {"kind": "until_revoked"}
    if text == "session":
        boot = c.store.get_setting("boot_id")
        if not boot:
            die("a session grant needs the broker to be running")
        return {"kind": "session", "boot_id": boot}
    try:
        d = dt.datetime.fromisoformat(text)
    except ValueError:
        die("duration must be once, session, forever, or a date like 2026-12-31 or 2026-12-31T18:00")
    if d.timestamp() <= time.time():
        die("that date is in the past")
    return {"kind": "until", "expires_at": d.timestamp()}


def cmd_grant_add(c: Ctx) -> None:
    cr = c.cred(c.args.account)
    agent_id = c.agent_id(c.args.agent)
    try:
        origins = [normalize_origin(o) for o in (c.args.origin or cr.origins)]
    except OriginError as e:
        die(str(e))
    if not origins:
        die("this account has no approved website; approve one first with `gatehouse account edit`")
    missing = [o for o in origins if o not in cr.origins]
    if missing:
        die(f"not approved on the account: {', '.join(missing)}")
    gid = c.store.add_grant(agent_id, cr.id, origins, **_duration(c, c.args.duration))
    c.store.audit("grant_added", agent_id, cr.id, ",".join(origins), "allowed", c.args.duration[:20])
    print(f"Grant {gid}: {agent_id} may sign in to {cr.name!r} on {', '.join(origins)} ({c.args.duration}).")


def cmd_grant_list(c: Ctx) -> None:
    names = {x.id: x.name for x in c.vault.load(c.key)} if c.args.names else {}
    for g in c.store.grants():
        state = "revoked" if g["revoked_at"] else ("used" if g["kind"] == "once" and g["used_count"] else
                 "expired" if g["kind"] == "until" and g["expires_at"] <= time.time() else
                 "ended" if g["kind"] == "session" and g["boot_id"] != c.store.get_setting("boot_id") else "active")
        dur = {"until": f"until {when(g['expires_at'])}", "until_revoked": "until revoked"}.get(g["kind"], g["kind"])
        print(f"{g['id']}  {g['agent_id']}  {names.get(g['credential_id'], g['credential_id'])}  "
              f"{', '.join(json.loads(g['origins']))}  {dur}  uses={g['used_count']}  {state}")


def cmd_grant_revoke(c: Ctx) -> None:
    ok = c.store.revoke_grant(c.args.grant)
    if ok:
        c.store.audit("grant_revoked", result=c.args.grant[:20])
    print("Revoked; the agent can no longer use this credential. A website session it already holds stays valid "
          "until you sign it out on the website or clear it." if ok else "No active grant with that id.")


def cmd_approvals(c: Ctx) -> None:
    rows = c.store.approvals()
    for r in rows:
        print(f"{r['id']}  agent {r['agent_id']} wants account {r['credential_id']} on {r['origin']}  ({when(r['created_at'])})")
    if not rows:
        print("No pending approvals.")


def cmd_handoff(c: Ctx) -> None:
    s = c.store
    port = s.get_setting("port", str(DEFAULT_PORT))
    pending = json.loads(s.get_setting("handoffs", "[]") or "[]") if s.get_setting("boot_id") else []
    if c.args.urls:
        for h in pending:
            print(f"http://127.0.0.1:{port}/handoff/{h['token']}")
        return
    if not pending:
        print("No sign-in is waiting for you.")
        return
    names = {x.id: x.name for x in c.vault.load(c.key)}
    for h in pending:
        print(f"{names.get(h['account_id'], h['account_id'])} on {h['origin']} (agent {h['agent_id']}, "
              f"waiting since {when(h['created_at'])}):\n  link: http://127.0.0.1:{port}/handoff/{h['token']}\n"
              f"  code: {h['code']}")
    print("Open the link and enter the code. The code is shown only here; never paste it anywhere else.")


def cmd_approve(c: Ctx) -> None:
    row = next((r for r in c.store.approvals() if r["id"] == c.args.approval), None)
    if row is None:
        die("no pending approval with that id")
    cr = c.cred(row["credential_id"])
    if row["origin"] not in cr.origins:
        if not confirm(f"{row['origin']} is NOT yet an approved website for {cr.name!r}. Approve it for this account?"):
            return
        with c.vault.edit(c.key) as creds:
            x = next(x for x in creds if x.id == cr.id)
            x.origins = sorted(set(x.origins) | {row["origin"]})
            cr = x
    login_origin = normalize_origin(cr.login_url) if cr.login_url else row["origin"]
    origins = sorted({row["origin"], login_origin} & set(cr.origins))
    gid = c.store.add_grant(row["agent_id"], cr.id, origins, **_duration(c, c.args.duration))
    c.store.resolve_approval(row["id"], "approved")
    c.store.audit("approval", row["agent_id"], cr.id, row["origin"], "allowed", "approved")
    print(f"Approved as grant {gid}.")


def cmd_deny(c: Ctx) -> None:
    row = c.store.resolve_approval(c.args.approval, "denied")
    if row:
        c.store.audit("approval", row["agent_id"], row["credential_id"], row["origin"], "denied", "denied")
    print("Denied." if row else "No pending approval with that id.")


# --- audit / controls ----------------------------------------------------------------
def cmd_audit(c: Ctx) -> None:
    if c.args.retention_days is not None:
        c.store.set_setting("audit_retention_days", str(c.args.retention_days))
        print(f"Retention set to {c.args.retention_days} days; {c.store.prune_audit()} old entries removed.")
        return
    for r in reversed(c.store.audit_rows(c.args.limit)):
        print(f"{when(r['ts'])}  {r['action']:<14} agent={r['agent_id'] or '-'} account={r['credential_id'] or '-'} "
              f"site={r['origin'] or '-'} {r['decision'] or ''} {r['result'] or ''}")


def cmd_logins(c: Ctx) -> None:
    c.store.set_setting("logins_disabled", "1" if c.args.state == "disable" else "0")
    c.store.audit("logins_" + c.args.state + "d")
    print(f"New logins {c.args.state}d for all agents.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gatehouse", description="Credential broker for AI agents")
    p.add_argument("--passphrase-file", help="read the vault passphrase from an owner-only file instead of prompting")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(parent, name, fn, help_):
        sp = parent.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        return sp

    add(sub, "init", cmd_init, "create the vault")
    add(sub, "status", cmd_status, "show broker state")
    add(sub, "admin-token", cmd_admin_token, "issue a token for the app's admin API (prints it)").add_argument(
        "--max-age", type=float, default=12 * 3600, help="seconds before the token expires even if in use")
    add(sub, "selftest", cmd_selftest, "check that the running broker can unlock the vault and start a browser")
    sp = add(sub, "serve", cmd_serve, "run the broker")
    sp.add_argument("--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--headless", action="store_true", help="no browser window (human verification becomes impossible)")
    sp.add_argument("--chrome", help="path to the Chromium binary")
    sp.add_argument("--chrome-arg", action="append", help="extra Chromium argument (repeatable)")
    sp.add_argument("--locked", action="store_true", help="start without unlocking the vault")
    sp.add_argument("--human-timeout", type=float, default=300, help="seconds to wait for a person at a challenge")

    acc = sub.add_parser("account", help="manage accounts").add_subparsers(dest="sub", required=True)
    add(acc, "add", cmd_account_add, "add an account interactively")
    add(acc, "list", cmd_account_list, "list accounts (never shows passwords)")
    sp = add(acc, "edit", cmd_account_edit, "change an account")
    sp.add_argument("account")
    sp.add_argument("--name"); sp.add_argument("--username"); sp.add_argument("--login-url")
    sp.add_argument("--password", action="store_true", help="prompt for a new password")
    sp.add_argument("--totp", action="store_true", help="prompt for a TOTP secret")
    sp.add_argument("--approve-origin", action="append"); sp.add_argument("--remove-origin", action="append")
    sp.add_argument("--pre-click", action="append", help="CSS selector to click before the form appears (repeatable; '' clears)")
    sp.add_argument("--success-selector", help="CSS selector present only when signed in")
    add(acc, "remove", cmd_account_remove, "delete an account and revoke its grants").add_argument("account")
    add(acc, "unblock", cmd_account_unblock, "reset the failed-login counter").add_argument("account")

    sp = add(sub, "import", cmd_import, "selectively import from a CSV export")
    sp.add_argument("file")
    sp.add_argument("--keep-file", action="store_true", help="do not offer to delete the file afterwards")

    ag = sub.add_parser("agent", help="manage agents").add_subparsers(dest="sub", required=True)
    sp = add(ag, "add", cmd_agent_add, "register an agent and issue its keys")
    sp.add_argument("name"); sp.add_argument("--write-config", required=True, help="where to write the agent's API config; '-' prints it, with the browser endpoint, as JSON")
    sp = add(ag, "rotate", cmd_agent_rotate, "issue new keys for an agent, keeping its grants")
    sp.add_argument("agent"); sp.add_argument("--write-config", required=True, help="as for agent add")
    add(ag, "list", cmd_agent_list, "list agents")
    add(ag, "revoke", cmd_agent_revoke, "revoke an agent entirely").add_argument("agent")

    gr = sub.add_parser("grant", help="manage permissions").add_subparsers(dest="sub", required=True)
    sp = add(gr, "add", cmd_grant_add, "allow an agent to sign in to an account")
    sp.add_argument("--agent", required=True); sp.add_argument("--account", required=True)
    sp.add_argument("--origin", action="append", help="limit to these approved websites (default: all approved on the account)")
    sp.add_argument("--for", dest="duration", required=True, help="once | session | forever | YYYY-MM-DD[THH:MM]")
    add(gr, "list", cmd_grant_list, "list grants").add_argument("--names", action="store_true", help="show account names (unlocks the vault)")
    add(gr, "revoke", cmd_grant_revoke, "revoke a grant").add_argument("grant")

    add(sub, "approvals", cmd_approvals, "list requests waiting for you")
    add(sub, "handoff", cmd_handoff, "links for sign-ins waiting on a CAPTCHA or code from you").add_argument(
        "--urls", action="store_true", help="print only the links")
    sp = add(sub, "approve", cmd_approve, "approve a pending request")
    sp.add_argument("approval"); sp.add_argument("--for", dest="duration", required=True)
    add(sub, "deny", cmd_deny, "deny a pending request").add_argument("approval")

    sp = add(sub, "audit", cmd_audit, "show activity history")
    sp.add_argument("--limit", type=int, default=50); sp.add_argument("--retention-days", type=float)
    add(sub, "logins", cmd_logins, "global switch for new logins").add_argument("state", choices=["disable", "enable"])
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    args.fn(Ctx(args))


if __name__ == "__main__":
    main()
