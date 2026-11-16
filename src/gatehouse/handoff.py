"""Human handoff: let a person finish a CAPTCHA or MFA step in the broker's login tab.

The broker's browser may be headless or belong to another macOS user, so the person
cannot simply look at it. While a login waits for a human, the broker streams the
login tab as screenshots to a local page and replays the person's mouse and keyboard
into it. The page is reached through a one-time link that only the management CLI can
read; the first browser to open it gets a cookie and is the only one let in after that.
The gate stays shut throughout: agents see nothing of this.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import secrets
import time

from .cdp import Browser, CDPError

MAX_TEXT = 512
MOUSE_TYPES = {"mousePressed", "mouseReleased", "mouseMoved"}
BUTTONS = {"none", "left", "middle", "right"}


class Handoff:
    def __init__(self, request_id: str, agent_id: str, account_id: str, origin: str, browser: Browser, session_id: str):
        self.token = secrets.token_urlsafe(24)
        self.cookie: str | None = None
        self.request_id, self.agent_id, self.account_id, self.origin = request_id, agent_id, account_id, origin
        self.b, self.sid = browser, session_id
        self.created_at = time.time()
        self.closed = asyncio.Event()
        self._viewer = None
        self._size = (1280.0, 900.0)

    def public(self) -> dict:
        return {"token": self.token, "request_id": self.request_id, "agent_id": self.agent_id,
                "account_id": self.account_id, "origin": self.origin, "created_at": self.created_at}

    def claim(self, cookie: str | None) -> str | None:
        """Return the cookie to set on first open, '' if this browser already holds it, None if refused."""
        if self.cookie is None:
            self.cookie = secrets.token_urlsafe(24)
            return self.cookie
        return "" if cookie and hmac.compare_digest(cookie, self.cookie) else None

    def admits(self, cookie: str | None) -> bool:
        return bool(self.cookie and cookie and hmac.compare_digest(cookie, self.cookie))

    def close(self) -> None:
        self.closed.set()

    async def serve(self, ws) -> None:
        """Stream the login tab to one viewer and replay their input. A newer viewer replaces an older one."""
        if self._viewer is not None:
            await self._viewer.close(code=4000, message=b"opened elsewhere")
        self._viewer = ws
        frames: asyncio.Queue = asyncio.Queue(maxsize=1)

        def on_event(msg: dict) -> None:
            if msg.get("sessionId") != self.sid or msg.get("method") != "Page.screencastFrame":
                return
            p = msg.get("params") or {}
            asyncio.ensure_future(self._ack(p.get("sessionId")))
            meta = p.get("metadata") or {}
            self._size = (float(meta.get("deviceWidth") or self._size[0]), float(meta.get("deviceHeight") or self._size[1]))
            if frames.full():
                frames.get_nowait()
            frames.put_nowait({"t": "frame", "data": p.get("data", ""), "w": self._size[0], "h": self._size[1]})

        async def sender():
            while True:
                await ws.send_str(json.dumps(await frames.get()))

        async def until_closed():
            await self.closed.wait()
            try:
                await ws.send_str(json.dumps({"t": "done"}))
            finally:
                await ws.close()

        self.b.add_listener(on_event)
        tasks = [asyncio.create_task(sender()), asyncio.create_task(until_closed())]
        try:
            await self.b.call("Page.startScreencast", {"format": "jpeg", "quality": 75, "maxWidth": 1600,
                                                       "maxHeight": 1200, "everyNthFrame": 1}, self.sid)
            async for frame in ws:
                if frame.type.name != "TEXT" or self.closed.is_set():
                    break
                try:
                    await self._input(json.loads(frame.data))
                except (ValueError, TypeError, KeyError, CDPError):
                    continue  # a malformed or rejected event is dropped, never echoed
        except CDPError:
            pass
        finally:
            self.b.remove_listener(on_event)
            for t in tasks:
                t.cancel()
            if self._viewer is ws:
                self._viewer = None
                try:
                    await self.b.call("Page.stopScreencast", {}, self.sid, timeout=5)
                except CDPError:
                    pass

    async def _ack(self, frame_session) -> None:
        try:
            await self.b.call("Page.screencastFrameAck", {"sessionId": frame_session}, self.sid, timeout=5)
        except CDPError:
            pass

    async def _input(self, ev: dict) -> None:
        kind = ev["t"]
        mods = int(ev.get("mod", 0)) & 15
        if kind in ("mouse", "wheel"):
            x = min(max(float(ev["x"]), 0.0), 1.0) * self._size[0]
            y = min(max(float(ev["y"]), 0.0), 1.0) * self._size[1]
            if kind == "wheel":
                params = {"type": "mouseWheel", "x": x, "y": y, "deltaX": float(ev.get("dx", 0)),
                          "deltaY": float(ev.get("dy", 0)), "modifiers": mods}
            else:
                if ev["type"] not in MOUSE_TYPES or ev.get("button", "none") not in BUTTONS:
                    return
                params = {"type": ev["type"], "x": x, "y": y, "button": ev.get("button", "none"),
                          "clickCount": min(int(ev.get("clicks", 0)), 3), "modifiers": mods}
            await self.b.call("Input.dispatchMouseEvent", params, self.sid, timeout=5)
        elif kind == "key":
            text = str(ev.get("text", ""))[:4]
            typ = ev["type"]
            if typ not in ("keyDown", "keyUp"):
                return
            params = {"type": ("keyDown" if text else "rawKeyDown") if typ == "keyDown" else "keyUp",
                      "key": str(ev.get("key", ""))[:32], "code": str(ev.get("code", ""))[:32],
                      "windowsVirtualKeyCode": int(ev.get("keyCode", 0)), "modifiers": mods}
            if text and typ == "keyDown":
                params["text"] = params["unmodifiedText"] = text
            await self.b.call("Input.dispatchKeyEvent", params, self.sid, timeout=5)
        elif kind == "text":
            await self.b.call("Input.insertText", {"text": str(ev["text"])[:MAX_TEXT]}, self.sid, timeout=5)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Gatehouse verification</title>
<style>
  :root { --bg: #f6f6f4; --fg: #1d1d1b; --muted: #6b6b66; --line: #d9d9d4; --accent: #1a5fb4; }
  @media (prefers-color-scheme: dark) { :root { --bg: #18181a; --fg: #ececea; --muted: #9a9a95; --line: #333336; --accent: #78aeed; } }
  * { box-sizing: border-box; }
  body { margin: 0; font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Helvetica Neue", sans-serif; background: var(--bg); color: var(--fg); }
  header { padding: 14px 20px; border-bottom: 1px solid var(--line); display: flex; gap: 16px; align-items: baseline; flex-wrap: wrap; }
  h1 { font-size: 16px; margin: 0; }
  #status { color: var(--muted); }
  main { padding: 16px 20px; }
  #screen { display: block; max-width: 100%; height: auto; border: 1px solid var(--line); border-radius: 6px; cursor: default; outline: none; background: #fff; }
  #screen:focus { border-color: var(--accent); }
  p.hint { color: var(--muted); margin: 10px 0 0; max-width: 70ch; }
  .done { font-size: 18px; padding: 40px 0; }
</style></head>
<body>
<header><h1>Gatehouse: finish signing in to __ORIGIN__</h1><span id="status">connecting…</span></header>
<main>
  <img id="screen" tabindex="0" alt="Live view of the sign-in page">
  <p class="hint">This is the broker's sign-in tab, live. Click into it and solve the CAPTCHA or enter the code as you normally would. Your agent cannot see this page. It closes on its own once the site lets you through.</p>
</main>
<script>
(() => {
  const img = document.getElementById('screen'), status = document.getElementById('status');
  const ws = new WebSocket(location.href.replace(/^http/, 'ws').replace(/\\/?(\\?.*)?$/, '/ws'));
  const send = o => ws.readyState === 1 && ws.send(JSON.stringify(o));
  const mod = e => (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
  const pos = e => { const r = img.getBoundingClientRect(); return {x: (e.clientX - r.left) / r.width, y: (e.clientY - r.top) / r.height}; };
  const btn = e => ['left', 'middle', 'right'][e.button] || 'none';
  ws.onopen = () => { status.textContent = 'live'; img.focus(); };
  ws.onclose = () => { if (status.textContent !== 'done') status.textContent = 'disconnected; reload to retry'; };
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.t === 'frame') img.src = 'data:image/jpeg;base64,' + d.data;
    if (d.t === 'done') { status.textContent = 'done'; document.querySelector('main').innerHTML =
      '<p class="done">Thanks, the broker has taken it from here. You can close this tab.</p>'; }
  };
  let last = 0;
  img.addEventListener('mousemove', e => { const now = performance.now(); if (now - last < 30) return; last = now;
    send({t: 'mouse', type: 'mouseMoved', ...pos(e), button: 'none', mod: mod(e)}); });
  img.addEventListener('mousedown', e => { e.preventDefault(); img.focus(); send({t: 'mouse', type: 'mousePressed', ...pos(e), button: btn(e), clicks: e.detail || 1, mod: mod(e)}); });
  img.addEventListener('mouseup', e => { e.preventDefault(); send({t: 'mouse', type: 'mouseReleased', ...pos(e), button: btn(e), clicks: e.detail || 1, mod: mod(e)}); });
  img.addEventListener('contextmenu', e => e.preventDefault());
  img.addEventListener('dragstart', e => e.preventDefault());
  img.addEventListener('wheel', e => { e.preventDefault(); send({t: 'wheel', ...pos(e), dx: e.deltaX, dy: e.deltaY, mod: mod(e)}); }, {passive: false});
  const key = (type, e) => { if (e.metaKey && e.key === 'v') return; e.preventDefault();
    send({t: 'key', type, key: e.key, code: e.code, keyCode: e.keyCode, text: type === 'keyDown' && e.key.length === 1 && !e.ctrlKey && !e.metaKey ? e.key : (e.key === 'Enter' && type === 'keyDown' ? '\\r' : ''), mod: mod(e)}); };
  img.addEventListener('keydown', e => key('keyDown', e));
  img.addEventListener('keyup', e => key('keyUp', e));
  document.addEventListener('paste', e => { e.preventDefault(); send({t: 'text', text: e.clipboardData.getData('text')}); });
})();
</script>
</body></html>"""

GONE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Gatehouse verification</title>
<style>body{font:16px/1.5 -apple-system,sans-serif;margin:48px;color:#333}@media(prefers-color-scheme:dark){body{background:#18181a;color:#ddd}}</style>
</head><body><p>__MESSAGE__</p></body></html>"""
