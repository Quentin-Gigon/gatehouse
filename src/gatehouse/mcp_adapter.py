"""MCP adapter (stdio). Exposes the broker's agent API as tools.

Implements the small part of the Model Context Protocol needed for tools, on
the standard library only, so the adapter has no dependency of its own. It
holds the agent's request-signing key; it never sees credential values because
the broker never returns any.

Config: a JSON file {"url","agent_id","sign_key"} named by GATEHOUSE_AGENT_CONFIG.
"""
from __future__ import annotations

import json
import os
import sys
import time

from .client import BrokerClient

PROTOCOL = "2025-06-18"
WAITING = ("in_progress", "human_verification_required")

TOOLS = [
    {"name": "list_authorized_accounts",
     "description": "List the accounts the user has authorized you to sign in to. Returns names, usernames and websites, never passwords.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "request_login",
     "description": ("Ask the broker to sign the shared browser in to an authorized account. The broker types the credentials itself; "
                     "your browser connection is closed while it does and you must reconnect afterwards. Waits up to wait_seconds, "
                     "then returns a status: signed_in, already_signed_in, permission_required, permission_denied, vault_locked, "
                     "human_verification_required, login_failed, unsupported_login_flow or in_progress. Do not retry login_failed; "
                     "tell the user instead."),
     "inputSchema": {"type": "object", "required": ["account_id"], "properties": {
         "account_id": {"type": "string"}, "browser_session_id": {"type": "string", "description": "Defaults to your current browser session."},
         "wait_seconds": {"type": "number", "default": 60}}}},
    {"name": "get_login_status", "description": "Check a login request, e.g. while the user completes a CAPTCHA or MFA prompt.",
     "inputSchema": {"type": "object", "required": ["request_id"], "properties": {"request_id": {"type": "string"}}}},
    {"name": "logout",
     "description": "Remove the local browser session (cookies, storage) for an account's websites. Does not end the session on the website's servers.",
     "inputSchema": {"type": "object", "required": ["account_id"], "properties": {
         "account_id": {"type": "string"}, "browser_session_id": {"type": "string"}}}},
]


class Adapter:
    def __init__(self, client: BrokerClient):
        self.c = client

    def _session(self, args: dict) -> str | None:
        return args.get("browser_session_id") or self.c.call("/v1/browser")[1].get("browser_session_id")

    def tool(self, name: str, args: dict) -> dict:
        if name == "list_authorized_accounts":
            return self.c.call("/v1/accounts")[1]
        if name == "request_login":
            _, r = self.c.call("/v1/login", {"account_id": args.get("account_id"), "browser_session_id": self._session(args)})
            end = time.time() + min(float(args.get("wait_seconds", 60)), 600)
            while r.get("request_id") and r.get("status") == "in_progress" and time.time() < end:
                time.sleep(1.0)
                _, r = self.c.call("/v1/login/status", {"request_id": r["request_id"]})
            return r
        if name == "get_login_status":
            return self.c.call("/v1/login/status", {"request_id": args.get("request_id")})[1]
        if name == "logout":
            return self.c.call("/v1/logout", {"account_id": args.get("account_id"), "browser_session_id": self._session(args)})[1]
        raise KeyError(name)

    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:
            return None  # notification
        if method == "initialize":
            result = {"protocolVersion": (msg.get("params") or {}).get("protocolVersion", PROTOCOL),
                      "capabilities": {"tools": {}}, "serverInfo": {"name": "gatehouse", "version": "0.1.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                data = self.tool(params.get("name", ""), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(data)}], "isError": False}
            except KeyError:
                return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
            except Exception:
                result = {"content": [{"type": "text", "text": json.dumps({"status": "broker_unreachable"})}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}


def main() -> None:
    path = os.environ.get("GATEHOUSE_AGENT_CONFIG")
    if not path:
        print("GATEHOUSE_AGENT_CONFIG is not set", file=sys.stderr)
        raise SystemExit(2)
    with open(os.path.expanduser(path)) as f:
        cfg = json.load(f)
    adapter = Adapter(BrokerClient(cfg["url"], cfg["agent_id"], cfg["sign_key"]))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            reply = adapter.handle(json.loads(line))
        except ValueError:
            reply = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
