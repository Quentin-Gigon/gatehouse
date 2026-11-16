from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from gatehouse import login as L  # noqa: E402
from gatehouse.client import BrokerClient  # noqa: E402
from gatehouse.config import Paths  # noqa: E402
from gatehouse.server import Broker, serve  # noqa: E402
from gatehouse.vault import Vault, new_credential  # noqa: E402
from fakesite import PASSWORD, USER, Site  # noqa: E402

PASSPHRASE = "test passphrase only"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Env:
    """A running broker, a synthetic site on two origins, and one registered agent."""

    def __init__(self, tmp: Path):
        self.paths = Paths(tmp / "home")
        self.paths.ensure()
        self.site = Site()
        self.port_a, self.port_b, self.port = free_port(), free_port(), free_port()
        self.origin = f"http://127.0.0.1:{self.port_a}"
        self.other = f"http://127.0.0.1:{self.port_b}"
        self.site.other_origin = self.other
        self.site.approved = self.origin
        self.vault = Vault(self.paths.vault)
        self.key = self.vault.create(PASSPHRASE, n=2 ** 12)

    async def start(self):
        self.runners = []
        for port in (self.port_a, self.port_b):
            runner = web.AppRunner(self.site.app())
            await runner.setup()
            await web.TCPSite(runner, "127.0.0.1", port).start()
            self.runners.append(runner)
        self.broker = Broker(self.paths, self.key, self.port, headless=True, chrome_args=("--no-sandbox",) if os.geteuid() == 0 else (),
                             timeouts=L.Timeouts(navigation=15, step=6, human=6, settle=0.3))
        self.runners.append(await serve(self.broker))
        self.store = self.broker.store
        self.agent = self.store.add_agent("test-agent")
        self.client = BrokerClient(f"http://127.0.0.1:{self.port}", self.agent["agent_id"], self.agent["sign_key"])
        self.http = aiohttp.ClientSession()

    async def stop(self):
        await self.http.close()
        for r in reversed(self.runners):
            await r.cleanup()

    # helpers ---------------------------------------------------------------
    def add_account(self, path="/login", password=PASSWORD, origins=None, **kw) -> str:
        cred = new_credential("Synthetic Books", USER, password,
                              origins=[self.origin] if origins is None else origins,
                              login_url=self.origin + path, **kw)
        with self.vault.edit(self.key) as creds:
            creds.append(cred)
        return cred.id

    def grant(self, cid: str, kind="until_revoked", origins=None, agent_id=None, **kw) -> str:
        return self.store.add_grant(agent_id or self.agent["agent_id"], cid, origins or [self.origin], kind, **kw)

    async def api(self, path: str, payload: dict | None = None, client: BrokerClient | None = None):
        return await asyncio.to_thread((client or self.client).call, path, payload)

    async def session_id(self, client=None) -> str:
        code, r = await self.api("/v1/browser", client=client)
        assert "browser_session_id" in r, (code, r)
        return r["browser_session_id"]

    async def login(self, cid: str, wait: float = 40, client=None) -> dict:
        sid = await self.session_id(client)
        _, r = await self.api("/v1/login", {"account_id": cid, "browser_session_id": sid}, client)
        end = asyncio.get_event_loop().time() + wait
        while r.get("request_id") and r["status"] in (L.PENDING, L.HUMAN) and asyncio.get_event_loop().time() < end:
            await asyncio.sleep(0.3)
            _, r = await self.api("/v1/login/status", {"request_id": r["request_id"]}, client)
        return r

    def relay_url(self, token=None) -> str:
        return f"ws://127.0.0.1:{self.port}/cdp/{token or self.agent['cdp_token']}/devtools/browser"


class AgentCDP:
    """What an agent's browser tool does: speak DevTools protocol through the relay."""

    def __init__(self, ws):
        self.ws, self.n, self.events = ws, 0, []

    async def call(self, method, params=None, session_id=None):
        self.n += 1
        msg = {"id": self.n, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        await self.ws.send_str(json.dumps(msg))
        while True:
            frame = await self.ws.receive(timeout=20)
            if frame.type != aiohttp.WSMsgType.TEXT:
                raise ConnectionError("relay closed")
            reply = json.loads(frame.data)
            if reply.get("id") == self.n:
                return reply
            self.events.append(reply)

    async def page(self, url=None):
        """Attach to an existing page (or create one) and return its session id."""
        targets = (await self.call("Target.getTargets"))["result"]["targetInfos"]
        pages = [t for t in targets if t["type"] == "page"]
        tid = pages[0]["targetId"] if pages and url is None else \
            (await self.call("Target.createTarget", {"url": url or "about:blank"}))["result"]["targetId"]
        return (await self.call("Target.attachToTarget", {"targetId": tid, "flatten": True}))["result"]["sessionId"]

    async def evaluate(self, sid, expr):
        r = await self.call("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True}, sid)
        return r["result"]["result"].get("value")


@pytest_asyncio.fixture
async def env(tmp_path):
    e = Env(tmp_path)
    await e.start()
    yield e
    await e.stop()


@pytest_asyncio.fixture
async def agent_cdp(env):
    await env.session_id()
    ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
    yield AgentCDP(ws)
    await ws.close()
