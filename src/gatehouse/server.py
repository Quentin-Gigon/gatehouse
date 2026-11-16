"""The broker daemon: authenticated agent API plus the gated DevTools relay."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import time
import uuid
from dataclasses import dataclass, field

from aiohttp import web

from . import login as L
from .cdp import Browser, CDPError
from .handoff import GONE, PAGE, Handoff
from .config import Paths
from .origins import origin_of
from .policy import authorize, visible_accounts
from .store import Store
from .vault import Vault

CLOCK_SKEW = 60.0
MAX_BODY = 64 * 1024
MAX_FAILURES = 2
REQUEST_TTL = 3600.0
REVOKE_POLL = 2.0


def sign(sign_key: str, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    msg = "\n".join([method.upper(), path, ts, nonce, hashlib.sha256(body).hexdigest()]).encode()
    return hmac.new(sign_key.encode(), msg, hashlib.sha256).hexdigest()


@dataclass
class LoginRequest:
    id: str
    agent_id: str
    credential_id: str
    origin: str
    status: str = L.PENDING
    detail: str = "queued"
    created_at: float = field(default_factory=time.time)
    task: asyncio.Task | None = None

    def public(self) -> dict:
        return {"request_id": self.id, "account_id": self.credential_id, "status": self.status, "detail": self.detail}


class Broker:
    def __init__(self, paths: Paths, key: bytes | None, port: int, headless: bool = False,
                 chrome: str | None = None, chrome_args: tuple[str, ...] = (), timeouts: L.Timeouts | None = None):
        self.paths, self.key, self.port = paths, key, port
        self.store = Store(paths.db)
        self.vault = Vault(paths.vault)
        self.boot_id = secrets.token_hex(8)
        self.headless, self.chrome, self.chrome_args = headless, chrome, chrome_args
        self.timeouts = timeouts or L.Timeouts()
        self.browsers: dict[str, Browser] = {}
        self.session_ids: dict[str, str] = {}
        self.requests: dict[str, LoginRequest] = {}
        self._browser_locks: dict[str, asyncio.Lock] = {}
        self.handoffs: dict[str, Handoff] = {}

    # --- app -----------------------------------------------------------------
    def app(self) -> web.Application:
        app = web.Application(client_max_size=MAX_BODY, middlewares=[self._local_only])
        r = app.router
        r.add_post("/v1/accounts", self._api(self.h_accounts))
        r.add_post("/v1/browser", self._api(self.h_browser))
        r.add_post("/v1/login", self._api(self.h_login))
        r.add_post("/v1/login/status", self._api(self.h_status))
        r.add_post("/v1/login/cancel", self._api(self.h_cancel))
        r.add_post("/v1/logout", self._api(self.h_logout))
        r.add_get("/cdp/{token}/json/version", self.h_cdp_version)
        r.add_get("/cdp/{token}/json/version/", self.h_cdp_version)
        r.add_get("/cdp/{token}/devtools/browser", self.h_cdp_ws)
        r.add_get("/handoff/{token}", self.h_handoff_page)
        r.add_get("/handoff/{token}/", self.h_handoff_page)
        r.add_get("/handoff/{token}/ws", self.h_handoff_ws)
        app.on_startup.append(self._on_start)
        app.on_cleanup.append(self._on_stop)
        return app

    async def _on_start(self, app) -> None:
        self.store.set_setting("boot_id", self.boot_id)
        self.store.set_setting("port", str(self.port))
        self.store.set_setting("handoffs", "[]")
        self.store.prune_audit()
        self.store.audit("broker_started", result="unlocked" if self.key else "locked")
        self._reaper = asyncio.create_task(self._reap_revoked())

    async def _reap_revoked(self) -> None:
        """Shut down the browsers of agents that have been revoked."""
        while True:
            await asyncio.sleep(REVOKE_POLL * 5)
            for agent_id, b in list(self.browsers.items()):
                row = self.store.agent(agent_id)
                if (row is None or row["revoked_at"] is not None) and not b.lock.locked():
                    self.browsers.pop(agent_id, None)
                    self.session_ids.pop(agent_id, None)
                    await b.stop()

    async def _on_stop(self, app) -> None:
        self._reaper.cancel()
        self.store.set_setting("boot_id", "")
        self.store.set_setting("handoffs", "[]")
        for req in self.requests.values():
            if req.task and not req.task.done():
                req.task.cancel()
        for b in self.browsers.values():
            await b.stop()

    @web.middleware
    async def _local_only(self, request: web.Request, handler):
        """Refuse anything that looks like it came from a web page (DNS rebinding, cross-site requests)."""
        host = request.headers.get("Host", "")
        own = (f"127.0.0.1:{self.port}", f"localhost:{self.port}")
        origin = request.headers.get("Origin")
        # The handoff page is the one thing a browser legitimately opens; it may only talk to itself.
        same_page = request.path.startswith("/handoff/") and origin == f"http://{host}"
        if host not in own or (origin is not None and not same_page):
            return web.json_response({"error": "forbidden"}, status=403)
        return await handler(request)

    def _api(self, fn):
        async def handler(request: web.Request):
            body = await request.read()
            h = request.headers
            agent_id, ts, nonce, sig = (h.get("X-GH-Agent", ""), h.get("X-GH-Timestamp", ""),
                                        h.get("X-GH-Nonce", ""), h.get("X-GH-Signature", ""))
            agent = self.store.agent(agent_id) if agent_id else None
            # Compute a signature even for unknown agents so both paths cost the same.
            expected = sign(agent["sign_key"] if agent else "x" * 43, request.method, request.path, ts, nonce, body)
            ok = agent is not None and agent["revoked_at"] is None and hmac.compare_digest(expected, sig)
            try:
                fresh = abs(time.time() - float(ts)) <= CLOCK_SKEW
            except ValueError:
                fresh = False
            if not ok or not fresh or not 16 <= len(nonce) <= 128:
                self.store.audit("api_rejected", agent_id=agent_id[:32] if agent else None, decision="denied",
                                 result="bad_signature" if not ok else "stale_or_malformed")
                return web.json_response({"error": "unauthenticated"}, status=401)
            if not self.store.use_nonce(agent_id, nonce, float(ts), CLOCK_SKEW):
                self.store.audit("api_rejected", agent_id=agent_id, decision="denied", result="replay")
                return web.json_response({"error": "replayed request"}, status=401)
            try:
                payload = json.loads(body or b"{}")
                if not isinstance(payload, dict):
                    raise ValueError
            except ValueError:
                return web.json_response({"error": "invalid JSON body"}, status=400)
            return web.json_response(await fn(agent_id, payload))
        return handler

    # --- browser sessions ------------------------------------------------------
    async def browser_for(self, agent_id: str) -> Browser:
        lock = self._browser_locks.setdefault(agent_id, asyncio.Lock())
        async with lock:
            b = self.browsers.get(agent_id)
            if b is None or not b.alive:
                b = Browser(self.paths.profiles / agent_id, chrome=self.chrome, headless=self.headless,
                            extra_args=self.chrome_args)
                await b.start()
                self.browsers[agent_id] = b
                self.session_ids[agent_id] = "bs_" + secrets.token_hex(8)
                self.store.audit("browser_started", agent_id=agent_id)
            return b

    # --- API handlers ------------------------------------------------------------
    async def h_accounts(self, agent_id: str, p: dict) -> dict:
        if self.key is None:
            return {"status": L.VAULT_LOCKED, "accounts": []}
        return {"status": "ok", "accounts": visible_accounts(self.store, agent_id, self.vault.load(self.key), self.boot_id)}

    async def h_browser(self, agent_id: str, p: dict) -> dict:
        try:
            b = await self.browser_for(agent_id)
        except (CDPError, OSError):
            return {"status": "browser_unavailable"}
        return {"status": "ok", "browser_session_id": self.session_ids[agent_id], "gate_open": b.gate_open}

    async def h_login(self, agent_id: str, p: dict) -> dict:
        cid = str(p.get("account_id", ""))[:64]

        def out(status: str, detail: str, origin: str | None = None, decision: str = "denied") -> dict:
            self.store.audit("login_request", agent_id, cid or None, origin, decision, f"{status}:{detail}")
            return {"request_id": None, "account_id": cid, "status": status, "detail": detail}

        if self.key is None:
            return out(L.VAULT_LOCKED, "unlock_the_vault")
        cred = self.vault.get(self.key, cid) if cid else None
        if cred is None:
            return out(L.PERMISSION_DENIED, "not_authorized")
        history = self.store.grants(agent_id=agent_id, credential_id=cid)
        if not history:
            return out(L.PERMISSION_DENIED, "not_authorized")  # indistinguishable from an unknown account
        origin = origin_of(cred.login_url) if cred.login_url else None
        if origin is None or origin not in cred.origins:
            return out(L.PERMISSION_REQUIRED, "account_has_no_approved_login_address")
        if self.session_ids.get(agent_id) is None or p.get("browser_session_id") != self.session_ids[agent_id]:
            return out(L.PERMISSION_DENIED, "unknown_browser_session", origin)
        d = authorize(self.store, agent_id, cred, origin, self.boot_id)
        if not d.allowed:
            if d.reason == "no_grant" and any(g["revoked_at"] is None for g in history):
                self.store.request_approval(agent_id, cid, origin)
                return out(L.PERMISSION_REQUIRED, "grant_expired_or_does_not_cover_this_address", origin)
            return out(L.PERMISSION_DENIED, d.reason, origin)
        if self.store.failures(cid) >= MAX_FAILURES:
            return out(L.FAILED, "blocked_after_repeated_failures_user_must_reset", origin)
        for req in self.requests.values():
            if req.agent_id == agent_id and req.credential_id == cid and req.task and not req.task.done():
                return req.public()
        if d.kind == "once" and not self.store.consume_once(d.grant_id):
            self.store.request_approval(agent_id, cid, origin)
            return out(L.PERMISSION_REQUIRED, "single_use_grant_already_used", origin)
        grant = next(g for g in history if g["id"] == d.grant_id)
        allowed = [o for o in json.loads(grant["origins"]) if o in cred.origins]
        req = LoginRequest("req_" + uuid.uuid4().hex[:16], agent_id, cid, origin)
        self._prune_requests()
        self.requests[req.id] = req
        self.store.audit("login_request", agent_id, cid, origin, "allowed", "started")
        req.task = asyncio.create_task(self._run_login(req, cred, allowed, d.grant_id))
        return req.public()

    def _recheck(self, req: LoginRequest, grant_id: str):
        """Re-validate a queued login once it holds the browser: it may have waited minutes behind
        another login, during which the grant, the account or the switches may have changed."""
        cred = self.vault.get(self.key, req.credential_id) if self.key else None
        agent = self.store.agent(req.agent_id)
        g = next((x for x in self.store.grants(agent_id=req.agent_id, credential_id=req.credential_id)
                  if x["id"] == grant_id), None)
        now = time.time()
        if (cred is None or g is None or g["revoked_at"] is not None or agent is None or agent["revoked_at"] is not None
                or self.store.logins_disabled() or req.origin not in cred.origins
                or req.origin not in json.loads(g["origins"])
                or (g["kind"] == "until" and (g["expires_at"] is None or g["expires_at"] <= now))
                or (g["kind"] == "session" and g["boot_id"] != self.boot_id)):
            return None, []
        return cred, [o for o in json.loads(g["origins"]) if o in cred.origins]

    async def _run_login(self, req: LoginRequest, cred, allowed: list[str], grant_id: str) -> None:
        status, detail, run, browser = L.FAILED, "browser_error", None, None
        try:
            browser = await self.browser_for(req.agent_id)
            async with browser.lock:
                cred, allowed = self._recheck(req, grant_id)
                if cred is None:
                    status, detail = L.PERMISSION_DENIED, "revoked_before_use"
                    return

                def on_status(s: str, d: str) -> None:
                    req.status, req.detail = s, d
                    if s == L.HUMAN:
                        self._open_handoff(req, browser, run.sid)
                    else:
                        self._close_handoffs(req.id)

                run = L.LoginRun(browser, cred, allowed, self.timeouts, on_status=on_status)
                req.detail = "signing_in"
                try:
                    await browser.close_gate()
                    await run.open_tab()
                    status, detail = await run.run()
                finally:
                    # Cleanup runs to completion even if this task is cancelled (again) meanwhile;
                    # the gate reopens only on a browser that no longer holds the login tab.
                    await _uncancellable(self._hand_back(req.agent_id, browser, run, status in (L.SIGNED_IN, L.ALREADY)))
        except asyncio.CancelledError:
            status, detail = L.CANCELLED, "cancelled_by_agent"
        except CDPError:
            status, detail = L.FAILED, "browser_error"
        finally:
            self._close_handoffs(req.id)
            if status == L.FAILED and detail in ("credentials_rejected", "code_rejected"):
                self.store.record_failure(cred.id if cred else req.credential_id)
            elif status in (L.SIGNED_IN, L.ALREADY):
                self.store.clear_failures(req.credential_id)
                self.store.count_use(grant_id)
            if status == L.PERMISSION_REQUIRED and run is not None and run.unapproved_origin:
                self.store.request_approval(req.agent_id, req.credential_id, run.unapproved_origin)
            req.status, req.detail = status, detail
            self.store.audit("login_result", req.agent_id, req.credential_id, req.origin, "allowed", f"{status}:{detail}")

    async def _hand_back(self, agent_id: str, browser: Browser, run: L.LoginRun, signed_in: bool) -> None:
        self._close_handoffs_for_run(run)
        try:
            safe = await run.finish(signed_in)
        except Exception:
            safe = False
        if safe:
            browser.open_gate()
            return
        # The login tab may still exist: never give this browser back. Kill it; the next request
        # starts a fresh one on the same profile (cookies persist, nothing in memory does).
        self.store.audit("browser_discarded", agent_id, result="login_tab_not_destroyed")
        try:
            await browser.stop()
        finally:
            if self.browsers.get(agent_id) is browser:
                del self.browsers[agent_id]
                self.session_ids.pop(agent_id, None)
            browser.open_gate()

    def _close_handoffs_for_run(self, run: L.LoginRun) -> None:
        for token in [t for t, h in self.handoffs.items() if h.sid == run.sid]:
            self.handoffs.pop(token).close()
        self._publish_handoffs()

    # --- human handoff ---------------------------------------------------------------
    def _open_handoff(self, req: LoginRequest, browser: Browser, session_id: str) -> None:
        if any(h.request_id == req.id for h in self.handoffs.values()):
            return
        h = Handoff(req.id, req.agent_id, req.credential_id, req.origin, browser, session_id)
        self.handoffs[h.token] = h
        self._publish_handoffs()
        self.store.audit("handoff_opened", req.agent_id, req.credential_id, req.origin, "allowed")

    def _close_handoffs(self, request_id: str) -> None:
        for token in [t for t, h in self.handoffs.items() if h.request_id == request_id]:
            self.handoffs.pop(token).close()
        self._publish_handoffs()

    def _publish_handoffs(self) -> None:
        # Readable only by the management CLI (the broker user's own state file), never by agents.
        self.store.set_setting("handoffs", json.dumps([h.public() for h in self.handoffs.values()]))

    def _handoff(self, request: web.Request) -> Handoff | None:
        return self.handoffs.get(request.match_info["token"])

    @staticmethod
    def _html(body: str, status: int = 200, **headers) -> web.Response:
        return web.Response(text=body, content_type="text/html", status=status, headers={
            "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; img-src data:; style-src 'unsafe-inline'; "
                                       "script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            **headers})

    async def h_handoff_page(self, request: web.Request):
        h = self._handoff(request)
        if h is None:
            return self._html(GONE.replace("__MESSAGE__", "This verification link has expired or the sign-in has "
                                           "already finished. Run <code>gatehouse-admin handoff</code> for a current one."), 404)
        cookie = h.claim(request.cookies.get("gh_handoff"))
        if cookie is None:
            return self._html(GONE.replace("__MESSAGE__", "This link was already opened in another browser. "
                                           "Use that browser, or wait for the next verification request."), 403)
        resp = self._html(PAGE.replace("__ORIGIN__", h.origin.replace("&", "&amp;").replace("<", "&lt;")))
        if cookie:
            resp.set_cookie("gh_handoff", cookie, path=f"/handoff/{h.token}", httponly=True, samesite="Strict")
        return resp

    async def h_handoff_ws(self, request: web.Request):
        h = self._handoff(request)
        if h is None or not h.admits(request.cookies.get("gh_handoff")):
            return web.json_response({"error": "forbidden"}, status=403)
        ws = web.WebSocketResponse(max_msg_size=64 * 1024)
        await ws.prepare(request)
        await h.serve(ws)
        return ws

    def _prune_requests(self) -> None:
        cutoff = time.time() - REQUEST_TTL
        for rid in [r.id for r in self.requests.values() if r.created_at < cutoff and (not r.task or r.task.done())]:
            del self.requests[rid]

    def _own_request(self, agent_id: str, p: dict) -> LoginRequest | None:
        req = self.requests.get(str(p.get("request_id", "")))
        return req if req and req.agent_id == agent_id else None

    async def h_status(self, agent_id: str, p: dict) -> dict:
        req = self._own_request(agent_id, p)
        return req.public() if req else {"request_id": p.get("request_id"), "status": "unknown_request", "detail": "expired_or_not_yours"}

    async def h_cancel(self, agent_id: str, p: dict) -> dict:
        req = self._own_request(agent_id, p)
        if req is None:
            return {"request_id": p.get("request_id"), "status": "unknown_request", "detail": "expired_or_not_yours"}
        if req.task and not req.task.done():
            req.task.cancel()
            await asyncio.wait([req.task], timeout=15)
        return req.public()

    async def h_logout(self, agent_id: str, p: dict) -> dict:
        cid = str(p.get("account_id", ""))[:64]
        cred = self.vault.get(self.key, cid) if self.key and cid else None
        if cred is None or not self.store.grants(agent_id=agent_id, credential_id=cid):
            return {"account_id": cid, "status": L.PERMISSION_DENIED, "detail": "not_authorized"}
        if p.get("browser_session_id") != self.session_ids.get(agent_id):
            return {"account_id": cid, "status": L.PERMISSION_DENIED, "detail": "unknown_browser_session"}
        b = await self.browser_for(agent_id)
        async with b.lock:
            await L.clear_site_session(b, cred.origins)
        self.store.audit("logout", agent_id, cid, None, "allowed", "local_session_removed")
        return {"account_id": cid, "status": "local_session_removed",
                "detail": "cookies_and_storage_cleared_locally_website_session_may_still_be_valid"}

    # --- DevTools relay ------------------------------------------------------------
    async def h_cdp_version(self, request: web.Request):
        agent = self.store.agent_by_cdp_token(request.match_info["token"])
        if agent is None:
            return web.json_response({"error": "forbidden"}, status=403)
        b = await self.browser_for(agent["id"])
        return web.json_response({
            "Browser": b.version.get("product", "Chrome"), "Protocol-Version": b.version.get("protocolVersion", "1.3"),
            "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/cdp/{request.match_info['token']}/devtools/browser"})

    async def h_cdp_ws(self, request: web.Request):
        agent = self.store.agent_by_cdp_token(request.match_info["token"])
        if agent is None:
            return web.json_response({"error": "forbidden"}, status=403)
        b = await self.browser_for(agent["id"])
        if not b.gate_open:
            return web.json_response({"error": "protected login in progress; retry shortly"}, status=423)
        ws = web.WebSocketResponse(max_msg_size=256 * 1024 * 1024)
        await ws.prepare(request)
        watch = asyncio.create_task(self._close_when_revoked(agent["id"], ws))
        try:
            await b.serve_agent(ws)
        finally:
            watch.cancel()
        return ws

    async def _close_when_revoked(self, agent_id: str, ws) -> None:
        """Revocation must also end a browser connection the agent already holds, not just new ones."""
        while not ws.closed:
            await asyncio.sleep(REVOKE_POLL)
            row = self.store.agent(agent_id)
            if row is None or row["revoked_at"] is not None:
                await ws.close(code=1008, message=b"agent revoked")
                return


async def _uncancellable(coro) -> None:
    """Await `coro` to completion even if the caller is cancelled, possibly repeatedly; then re-raise."""
    task = asyncio.ensure_future(coro)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    if cancelled:
        raise asyncio.CancelledError
    task.result()


async def serve(broker: Broker) -> web.AppRunner:
    runner = web.AppRunner(broker.app(), access_log=None)  # no access log: paths carry relay tokens
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", broker.port).start()
    return runner
