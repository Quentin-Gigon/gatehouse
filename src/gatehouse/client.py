"""Minimal signing client for the agent API. Standard library only."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.request


def sign(sign_key: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    msg = "\n".join([method.upper(), path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    return hmac.new(sign_key.encode(), msg, hashlib.sha256).hexdigest()


class BrokerClient:
    def __init__(self, url: str, agent_id: str, sign_key: str):
        self.url, self.agent_id, self.sign_key = url.rstrip("/"), agent_id, sign_key

    def headers(self, path: str, body: bytes, ts: str | None = None, nonce: str | None = None) -> dict:
        ts = ts or str(time.time())
        nonce = nonce or secrets.token_urlsafe(18)
        return {"Content-Type": "application/json", "X-GH-Agent": self.agent_id, "X-GH-Timestamp": ts,
                "X-GH-Nonce": nonce, "X-GH-Signature": sign(self.sign_key, "POST", path, ts, nonce, body)}

    def call(self, path: str, payload: dict | None = None, headers: dict | None = None) -> tuple[int, dict]:
        body = json.dumps(payload or {}).encode()
        req = urllib.request.Request(self.url + path, data=body, method="POST", headers=headers or self.headers(path, body))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route through a proxy
        try:
            with opener.open(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")
