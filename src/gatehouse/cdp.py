"""Broker-owned Chromium and the gated DevTools channel.

Chromium is started with --remote-debugging-pipe, so its DevTools protocol is
reachable only through two file descriptors held by this process. There is no
debugging port for anything else on the machine to connect to.

Agents drive the browser through `serve_agent`, which relays DevTools messages
over a WebSocket. That relay is a gate: `close_gate` disconnects every agent,
detaches every DevTools session they created and resets browser-level state, so
the broker has the browser to itself while it types a secret.

Nothing in this module logs message contents.
"""
from __future__ import annotations

import asyncio
import fcntl
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

INTERNAL = object()  # owner marker for the broker's own sessions


class CDPError(Exception):
    pass


CHROME_CANDIDATES = (
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "chromium", "chromium-browser", "google-chrome",
)


def find_chrome(explicit: str | None = None) -> str:
    for cand in ([explicit] if explicit else []) + [os.environ.get("GATEHOUSE_CHROME", "")] + list(CHROME_CANDIDATES):
        if cand and (os.path.isfile(cand) or shutil.which(cand)):
            return cand if os.path.isfile(cand) else shutil.which(cand)
    raise CDPError("no Chromium found; set GATEHOUSE_CHROME")


# --- what an agent may send ------------------------------------------------

# Browser-level commands (no page session). Allowlist: this state outlives an
# agent's connection, so only commands we can reason about get through.
ROOT_ALLOW = {
    "Browser.getVersion", "Browser.getWindowForTarget", "Browser.getWindowBounds", "Browser.setWindowBounds",
    "Browser.grantPermissions", "Browser.resetPermissions",
    "Storage.getCookies", "Storage.setCookies", "Storage.clearCookies",
    "Target.getTargets", "Target.getTargetInfo", "Target.attachToTarget", "Target.detachFromTarget",
    "Target.createTarget", "Target.closeTarget", "Target.activateTarget", "Target.setAutoAttach",
    "Target.setDiscoverTargets", "Target.getBrowserContexts", "Target.createBrowserContext",
    "Target.disposeBrowserContext",
}
# Accepted and answered with an empty result without reaching the browser.
STUB = {"Browser.setDownloadBehavior", "Page.setDownloadBehavior"}
# Refused everywhere. sendMessageToTarget would tunnel commands past this filter.
DENY = {
    "Target.exposeDevToolsProtocol", "Target.attachToBrowserTarget", "Target.setRemoteLocations",
    "Target.sendMessageToTarget",
    "Browser.close", "Browser.crash", "Browser.crashGpuProcess",
    "DOM.setFileInputFiles", "Page.setInterceptFileChooserDialog", "Page.handleFileChooser",
    "Input.dispatchDragEvent", "Input.setInterceptDrags",
    "Security.setIgnoreCertificateErrors", "Security.setOverrideCertificateErrors",
    "Network.setCertificateOverride", "Page.setBypassCSP",
}
DENY_PREFIX = ("Tracing.", "Extensions.", "SystemInfo.", "Tethering.", "Cast.", "Memory.", "HeapProfiler.")
URL_METHODS = {"Page.navigate", "Target.createTarget", "Network.loadNetworkResource"}
# Every agent session must be flat, so each command arrives as a top-level message this filter sees.
FORCE_FLATTEN = {"Target.attachToTarget", "Target.setAutoAttach"}


def check_agent_command(msg: dict, rootlike: bool) -> str | None:
    """Return None to forward, 'stub' to answer locally, or a refusal reason. May rewrite params."""
    method = msg.get("method")
    if not isinstance(method, str) or not isinstance(msg.get("id"), int):
        return "malformed"
    if msg.get("params") is not None and not isinstance(msg["params"], dict):
        return "malformed"
    if method in STUB:
        return "stub"
    if method in DENY or method.startswith(DENY_PREFIX):
        return "not permitted by broker"
    if rootlike and method not in ROOT_ALLOW:
        return "not permitted by broker at browser level"
    if method in FORCE_FLATTEN:
        msg["params"] = {**(msg.get("params") or {}), "flatten": True}
    if method in URL_METHODS:
        url = (msg.get("params") or {}).get("url", "")
        if url not in ("", "about:blank") and urlsplit(url).scheme.lower() not in ("http", "https"):
            return "only http(s) addresses are permitted"
    return None


class _Agent:
    def __init__(self, ws):
        self.ws = ws
        self.out: asyncio.Queue = asyncio.Queue()


class Browser:
    def __init__(self, profile_dir: Path, chrome: str | None = None, headless: bool = False,
                 extra_args: tuple[str, ...] = ()):
        self.profile_dir = Path(profile_dir)
        self.chrome = find_chrome(chrome)
        self.headless = headless
        self.extra_args = extra_args
        self.proc: subprocess.Popen | None = None
        self.lock = asyncio.Lock()          # one protected login at a time
        self.gate_open = True
        self._next_id = 0
        self._pending: dict[int, tuple] = {}
        self._sessions: dict[str, object] = {}   # sessionId -> owner (_Agent | INTERNAL | None)
        self._rootlike: set[str] = set()
        self._agents: set[_Agent] = set()
        self._listeners: list = []
        self._reader_task: asyncio.Task | None = None
        self._w = None
        self.version: dict = {}

    # --- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        self.profile_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._write_prefs()
        to_chrome_r, to_chrome_w = os.pipe()
        from_chrome_r, from_chrome_w = os.pipe()
        # Move the child's ends above 9 so they cannot collide with 3 and 4 in the child.
        for name in ("to_chrome_r", "from_chrome_w"):
            fd = locals()[name]
            high = fcntl.fcntl(fd, fcntl.F_DUPFD, 10)
            os.close(fd)
            if name == "to_chrome_r":
                to_chrome_r = high
            else:
                from_chrome_w = high
        args = [self.chrome, "--remote-debugging-pipe", f"--user-data-dir={self.profile_dir}",
                "--no-first-run", "--no-default-browser-check", "--disable-extensions",
                "--disable-sync", "--disable-background-networking", "--password-store=basic",
                "--use-mock-keychain",
                "--disable-features=PasswordManagerOnboarding,AutofillServerCommunication,BackForwardCache",
                "--disable-blink-features=AutomationControlled",
                *(self._headless_args() if self.headless else ()), *self.extra_args, "about:blank"]
        # Chromium expects the pipe on descriptors 3 (read) and 4 (write). A tiny trampoline
        # puts them there and then becomes Chromium; no shell is involved.
        trampoline = ("import os,sys;os.dup2(int(sys.argv[1]),3);os.dup2(int(sys.argv[2]),4);"
                      "os.execv(sys.argv[3],sys.argv[3:])")
        self.proc = subprocess.Popen([sys.executable, "-I", "-c", trampoline, str(to_chrome_r), str(from_chrome_w), *args],
                                     pass_fds=(to_chrome_r, from_chrome_w), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(to_chrome_r)
        os.close(from_chrome_w)
        loop = asyncio.get_running_loop()
        self._w = os.fdopen(to_chrome_w, "wb", buffering=0)
        self._reader_task = loop.create_task(self._read_loop(from_chrome_r))
        self.version = await self.call("Browser.getVersion", timeout=30)

    def _headless_args(self) -> tuple[str, ...]:
        """Headless Chromium announces itself as HeadlessChrome in a tiny window; many sites
        answer that with a CAPTCHA. Present a desktop-sized window and the regular user agent."""
        args = ["--headless=new", "--window-size=1280,900"]
        if any(a.startswith("--user-agent=") for a in self.extra_args):
            return tuple(args)
        try:
            out = subprocess.run([self.chrome, "--version"], capture_output=True, text=True, timeout=30).stdout
            major = next(w for w in out.split() if w[:1].isdigit()).split(".")[0]
        except (OSError, subprocess.SubprocessError, StopIteration):
            return tuple(args)
        platform = {"darwin": "Macintosh; Intel Mac OS X 10_15_7"}.get(sys.platform, "X11; Linux x86_64")
        args.append(f"--user-agent=Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) "
                    f"Chrome/{major}.0.0.0 Safari/537.36")
        return tuple(args)

    def _write_prefs(self) -> None:
        """Turn off Chromium's own password saving before first launch."""
        default = self.profile_dir / "Default"
        default.mkdir(mode=0o700, parents=True, exist_ok=True)
        prefs_path = default / "Preferences"
        prefs = {}
        if prefs_path.exists():
            try:
                prefs = json.loads(prefs_path.read_text())
            except ValueError:
                prefs = {}
        prefs["credentials_enable_service"] = False
        prefs["credentials_enable_autosignin"] = False
        prefs.setdefault("profile", {})["password_manager_enabled"] = False
        prefs.setdefault("autofill", {}).update({"profile_enabled": False, "credit_card_enabled": False})
        prefs_path.write_text(json.dumps(prefs))

    async def stop(self) -> None:
        if self._reader_task:
            self._reader_task.cancel()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                await asyncio.get_running_loop().run_in_executor(None, self.proc.wait, 5)
            except Exception:
                self.proc.kill()
        if self._w:
            self._w.close()

    @property
    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    # --- transport ---------------------------------------------------------
    async def _read_loop(self, fd: int) -> None:
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=2 ** 30)
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), os.fdopen(fd, "rb", buffering=0))
        buf = bytearray()
        while True:
            chunk = await reader.read(1 << 16)
            if not chunk:
                break
            buf += chunk
            while (i := buf.find(b"\0")) >= 0:
                raw, buf = bytes(buf[:i]), buf[i + 1:]
                try:
                    self._dispatch(json.loads(raw))
                except Exception:
                    pass  # never let one bad message, or its contents, escape
        for entry in self._pending.values():
            if entry[0] is INTERNAL and not entry[2].done():
                entry[2].set_exception(CDPError("browser closed"))
        for a in list(self._agents):
            a.out.put_nowait(None)

    def _send(self, msg: dict) -> None:
        data = memoryview(json.dumps(msg, separators=(",", ":")).encode() + b"\0")
        while data:
            data = data[self._w.write(data):]

    def _dispatch(self, msg: dict) -> None:
        if "id" in msg:
            entry = self._pending.pop(msg["id"], None)
            if entry is None:
                return
            owner, orig_id, extra = entry
            sid = (msg.get("result") or {}).get("sessionId")
            if sid and extra == "Target.attachToTarget" or (owner is INTERNAL and sid):
                self._sessions[sid] = owner
            if owner is INTERNAL:
                if not extra.done():
                    extra.set_result(msg)
            elif owner in self._agents:
                msg["id"] = orig_id
                owner.out.put_nowait(msg)
            return
        method, sid, params = msg.get("method"), msg.get("sessionId"), msg.get("params") or {}
        if method == "Target.attachedToTarget":
            child = params.get("sessionId")
            self._sessions.setdefault(child, self._sessions.get(sid) if sid else None)
            if (params.get("targetInfo") or {}).get("type") == "browser" or sid in self._rootlike:
                self._rootlike.add(child)
        elif method == "Target.detachedFromTarget":
            self._sessions.pop(params.get("sessionId"), None)
            self._rootlike.discard(params.get("sessionId"))
        owner = self._sessions.get(sid) if sid else None
        if owner is INTERNAL:
            for cb in self._listeners:
                cb(msg)
        elif owner is not None:
            if owner in self._agents:
                owner.out.put_nowait(msg)
        else:
            for a in self._agents:
                a.out.put_nowait(msg)
            for cb in self._listeners:
                cb(msg)

    # --- broker's own client -------------------------------------------------
    async def call(self, method: str, params: dict | None = None, session_id: str | None = None,
                   timeout: float = 30) -> dict:
        self._next_id += 1
        fut = asyncio.get_running_loop().create_future()
        self._pending[self._next_id] = (INTERNAL, None, fut)
        msg = {"id": self._next_id, "method": method, "params": params or {}}
        if session_id:
            msg["sessionId"] = session_id
        self._send(msg)
        try:
            reply = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            raise CDPError(f"{method} timed out") from None
        if "error" in reply:
            raise CDPError(f"{method} failed")  # deliberately no browser-supplied text
        return reply.get("result") or {}

    def add_listener(self, cb) -> None:
        self._listeners.append(cb)

    def remove_listener(self, cb) -> None:
        if cb in self._listeners:
            self._listeners.remove(cb)

    # --- gate ----------------------------------------------------------------
    async def close_gate(self) -> None:
        """Disconnect all agents and remove everything they left attached."""
        self.gate_open = False
        for a in list(self._agents):
            a.out.put_nowait(None)
            try:
                await a.ws.close(code=1012, message=b"protected login in progress")
            except Exception:
                pass
        self._agents.clear()
        await self._reset(lambda owner: owner is not INTERNAL)

    def open_gate(self) -> None:
        self.gate_open = True

    async def _reset(self, match) -> None:
        for sid, owner in list(self._sessions.items()):
            if match(owner):
                try:
                    await self.call("Target.detachFromTarget", {"sessionId": sid}, timeout=5)
                except CDPError:
                    pass
                self._sessions.pop(sid, None)
                self._rootlike.discard(sid)
        if not self._agents:
            for method, params in (("Target.setAutoAttach", {"autoAttach": False, "waitForDebuggerOnStart": False, "flatten": True}),
                                   ("Target.setDiscoverTargets", {"discover": False})):
                try:
                    await self.call(method, params, timeout=5)
                except CDPError:
                    pass

    # --- agent relay -----------------------------------------------------------
    async def serve_agent(self, ws) -> None:
        """Relay DevTools messages for one agent WebSocket until it closes or the gate shuts."""
        if not self.gate_open:
            await ws.close(code=1013, message=b"protected login in progress")
            return
        agent = _Agent(ws)
        self._agents.add(agent)

        async def writer():
            while (msg := await agent.out.get()) is not None:
                try:
                    await ws.send_str(json.dumps(msg, separators=(",", ":")))
                except Exception:
                    return

        wtask = asyncio.create_task(writer())
        try:
            async for frame in ws:
                if frame.type.name != "TEXT" or not self.gate_open or agent not in self._agents:
                    break
                try:
                    msg = json.loads(frame.data)
                except ValueError:
                    break
                sid = msg.get("sessionId")
                verdict = check_agent_command(msg, rootlike=(sid is None or sid in self._rootlike))
                if verdict is None and sid is not None and self._sessions.get(sid, agent) not in (agent, None):
                    verdict = "unknown session"
                if verdict == "stub":
                    agent.out.put_nowait({"id": msg["id"], "result": {}, **({"sessionId": sid} if sid else {})})
                elif verdict is not None:
                    if isinstance(msg.get("id"), int):
                        agent.out.put_nowait({"id": msg["id"], "error": {"code": -32000, "message": verdict},
                                              **({"sessionId": sid} if sid else {})})
                else:
                    self._next_id += 1
                    self._pending[self._next_id] = (agent, msg["id"], msg["method"])
                    msg["id"] = self._next_id
                    self._send(msg)
        finally:
            agent.out.put_nowait(None)
            wtask.cancel()
            if agent in self._agents:
                self._agents.discard(agent)
                if self.gate_open:
                    await self._reset(lambda owner: owner is agent or (owner is None and not self._agents))
