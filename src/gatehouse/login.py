"""Password login inside a broker-owned tab.

Runs only while the gate is closed. Every script that touches a field first
checks, in the same JavaScript turn, that the top-level document is on an
authorized origin and that the form posts to one. Secrets go to the browser
over the debugging pipe and nowhere else; statuses and details are fixed words.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from . import totp as totp_mod
from .cdp import Browser, CDPError
from .origins import origin_of
from .vault import Credential

# Statuses returned to agents.
SIGNED_IN = "signed_in"
ALREADY = "already_signed_in"
PERMISSION_REQUIRED = "permission_required"
PERMISSION_DENIED = "permission_denied"
VAULT_LOCKED = "vault_locked"
HUMAN = "human_verification_required"
FAILED = "login_failed"
UNSUPPORTED = "unsupported_login_flow"
PENDING = "in_progress"
CANCELLED = "cancelled"

_LIB = r"""
const vis = el => { const r = el.getBoundingClientRect(), s = getComputedStyle(el);
  return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !el.disabled && !el.readOnly; };
const key = i => [i.name, i.id, i.autocomplete, i.getAttribute('aria-label') || '', i.placeholder || ''].join(' ');
const find = () => {
  const inputs = [...document.querySelectorAll('input')].filter(vis);
  const pw = inputs.filter(i => i.type === 'password');
  const otp = inputs.filter(i => i.type !== 'password' && (i.autocomplete === 'one-time-code' ||
    /otp|totp|2fa|mfa|verification.?code|auth.?code|one.?time/i.test(key(i))));
  const texty = inputs.filter(i => ['email', 'text', 'tel', ''].includes(i.type) && !otp.includes(i));
  let user = texty.filter(i => /user|email|login|identifier|account/i.test(key(i)) || i.type === 'email');
  if (!user.length && pw.length) user = texty.filter(i => i.form && i.form === pw[0].form);
  return {inputs, pw, otp, user};
};
const formOk = (el, allowed) => { const a = el.form && el.form.getAttribute('action');
  if (!a) return true; try { return allowed.includes(new URL(a, location.href).origin); } catch (e) { return false; } };
"""

_STATE = "(sel => {" + _LIB + r"""
  const f = find();
  const captcha = !!document.querySelector('iframe[src*="recaptcha"],iframe[src*="hcaptcha"],iframe[src*="turnstile"],' +
    'iframe[src*="arkoselabs"],iframe[title*="captcha" i],.g-recaptcha,.h-captcha,[id*="captcha" i],[name*="captcha" i],img[src*="captcha" i]');
  let ok = false; try { ok = !!(sel && document.querySelector(sel)); } catch (e) {}
  return JSON.stringify({origin: location.origin, href: location.href, ready: document.readyState,
    pw: f.pw.length, user: f.user.length, otp: f.otp.length, captcha, success: ok,
    sig: location.href + '|' + f.inputs.map(i => i.type + ':' + i.name + ':' + i.id).join(',')});
})"""

_FILL = "((allowed, kind, value) => {" + _LIB + r"""
  if (window.top !== window || !allowed.includes(location.origin)) return 'origin_mismatch';
  const el = find()[kind][0];
  if (!el) return 'no_field';
  if (!formOk(el, allowed)) return 'form_action_mismatch';
  el.focus();
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
  el.dispatchEvent(new Event('input', {bubbles: true}));
  el.dispatchEvent(new Event('change', {bubbles: true}));
  return 'ok';
})"""

_SUBMIT = "((allowed, kind) => {" + _LIB + r"""
  if (window.top !== window || !allowed.includes(location.origin)) return 'origin_mismatch';
  const el = find()[kind][0];
  if (!el) return 'no_field';
  if (!formOk(el, allowed)) return 'form_action_mismatch';
  const form = el.form;
  if (!form) { el.focus(); return 'enter'; }
  const btn = [...form.querySelectorAll('button[type=submit],input[type=submit],button:not([type])')].filter(vis)[0];
  if (btn) btn.click(); else if (form.requestSubmit) form.requestSubmit(); else form.submit();
  return 'ok';
})"""

_CLICK = "((allowed, sel) => {" + r"""
  if (window.top !== window || !allowed.includes(location.origin)) return 'origin_mismatch';
  let el = null; try { el = document.querySelector(sel); } catch (e) {}
  if (!el) return 'no_element';
  el.click(); return 'ok';
})"""

_SCRUB = r"""(() => { for (const i of document.querySelectorAll('input[type=password]')) {
  try { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(i, ''); } catch (e) {} } return 'ok'; })"""


@dataclass
class Timeouts:
    navigation: float = 30.0
    step: float = 20.0
    human: float = 300.0
    settle: float = 0.6


class _Abort(Exception):
    def __init__(self, status: str, detail: str):
        self.status, self.detail = status, detail


class LoginRun:
    """One login attempt. At most one password submission, ever."""

    def __init__(self, browser: Browser, cred: Credential, allowed: list[str], timeouts: Timeouts | None = None,
                 on_status=None):
        self.b, self.cred, self.allowed = browser, cred, allowed
        self.t = timeouts or Timeouts()
        self.on_status = on_status or (lambda status, detail: None)
        self.sid: str | None = None
        self.target: str | None = None
        self.unapproved_origin: str | None = None

    async def _eval(self, fn: str, *args, retries: int = 20):
        expr = f"{fn}({', '.join(json.dumps(a) for a in args)})"
        for _ in range(retries):
            try:
                r = await self.b.call("Runtime.evaluate", {"expression": expr, "returnByValue": True}, self.sid)
            except CDPError:
                await asyncio.sleep(0.25)  # execution context replaced by a navigation
                continue
            if "exceptionDetails" in r:
                raise _Abort(UNSUPPORTED, "script_error")
            return r["result"].get("value")
        raise _Abort(FAILED, "page_unresponsive")

    async def _state(self) -> dict:
        return json.loads(await self._eval(_STATE, self.cred.success_selector or ""))

    async def _wait_ready(self, timeout: float) -> dict:
        end = time.monotonic() + timeout
        while True:
            st = await self._state()
            if st["ready"] == "complete" or time.monotonic() > end:
                return st
            await asyncio.sleep(0.25)

    async def _wait_change(self, sig: str) -> dict:
        end = time.monotonic() + self.t.step
        while time.monotonic() < end:
            await asyncio.sleep(0.25)
            st = await self._state()
            if st["sig"] != sig and st["ready"] == "complete":
                await asyncio.sleep(self.t.settle)
                return await self._wait_ready(self.t.navigation)
        return await self._state()

    async def _fill(self, kind: str, value: str) -> None:
        r = await self._eval(_FILL, self.allowed, kind, value)
        if r != "ok":
            raise _Abort(FAILED if r != "no_field" else UNSUPPORTED, r)

    async def _submit(self, kind: str) -> None:
        r = await self._eval(_SUBMIT, self.allowed, kind)
        if r == "enter":
            for typ in ("keyDown", "keyUp"):
                await self.b.call("Input.dispatchKeyEvent", {"type": typ, "key": "Enter", "code": "Enter",
                                  "windowsVirtualKeyCode": 13, "text": "\r" if typ == "keyDown" else ""}, self.sid)
        elif r != "ok":
            raise _Abort(FAILED, r)

    async def _human(self, done) -> dict:
        """Hold the gate shut while a person finishes a challenge in the browser window."""
        self.on_status(HUMAN, "waiting_for_user")
        end = time.monotonic() + self.t.human
        while time.monotonic() < end:
            await asyncio.sleep(1.0)
            st = await self._state()
            if done(st):
                self.on_status(PENDING, "resumed")
                return st
        raise _Abort(FAILED, "human_verification_timeout")

    async def open_tab(self) -> None:
        """Create the login tab, then close every other tab and clear what could carry planted code."""
        self.target = (await self.b.call("Target.createTarget", {"url": "about:blank"}))["targetId"]
        self.sid = (await self.b.call("Target.attachToTarget", {"targetId": self.target, "flatten": True}))["sessionId"]
        for t in (await self.b.call("Target.getTargets"))["targetInfos"]:
            if t["targetId"] != self.target and t["type"] in ("page", "iframe", "webview", "background_page", "other"):
                try:
                    await self.b.call("Target.closeTarget", {"targetId": t["targetId"]}, timeout=5)
                except CDPError:
                    pass
        for origin in self.allowed:
            try:
                await self.b.call("Storage.clearDataForOrigin",
                                  {"origin": origin, "storageTypes": "service_workers,cache_storage"}, self.sid)
            except CDPError:
                pass
        try:
            await self.b.call("Network.clearBrowserCache", {}, self.sid)
        except CDPError:
            pass

    async def run(self) -> tuple[str, str]:
        try:
            return await self._run()
        except _Abort as a:
            return a.status, a.detail
        except CDPError:
            return FAILED, "browser_error"

    async def _run(self) -> tuple[str, str]:
        cred = self.cred
        await self.b.call("Page.enable", {}, self.sid)
        nav = await self.b.call("Page.navigate", {"url": cred.login_url}, self.sid, timeout=self.t.navigation)
        if nav.get("errorText"):
            raise _Abort(FAILED, "navigation_error")
        st = await self._wait_ready(self.t.navigation)
        await asyncio.sleep(self.t.settle)
        st = await self._state()
        for sel in cred.pre_click:
            if st["pw"] or st["user"] or st["success"]:
                break
            if await self._eval(_CLICK, self.allowed, sel) == "ok":
                st = await self._wait_change(st["sig"])
        pw_done = user_done = otp_done = False
        for _ in range(8):
            if st["origin"] not in self.allowed:
                if pw_done and not st["pw"] and not st["otp"] and not cred.success_selector:
                    return SIGNED_IN, "left_approved_origins_after_login"
                self.unapproved_origin = origin_of(st["origin"])
                raise _Abort(PERMISSION_REQUIRED, "redirected_to_unapproved_origin")
            if st["success"]:
                return (SIGNED_IN, "verified") if pw_done else (ALREADY, "verified")
            if st["pw"]:
                if pw_done:
                    if st["captcha"]:
                        st = await self._human(lambda s: s["success"] or not s["pw"])
                        continue
                    raise _Abort(FAILED, "credentials_rejected")
                if st["user"]:
                    await self._fill("user", cred.username)
                await self._fill("pw", cred.password)
                pw_done = True
                await self._submit("pw")
                st = await self._wait_change(st["sig"])
            elif st["otp"]:
                if cred.totp and not otp_done:
                    await self._fill("otp", totp_mod.code(cred.totp))
                    otp_done = True
                    await self._submit("otp")
                    st = await self._wait_change(st["sig"])
                elif otp_done:
                    raise _Abort(FAILED, "code_rejected")
                else:
                    st = await self._human(lambda s: s["success"] or not s["otp"])
            elif st["user"] and not pw_done:
                if user_done:
                    raise _Abort(FAILED, "username_step_rejected")
                await self._fill("user", cred.username)
                user_done = True
                await self._submit("user")
                st = await self._wait_change(st["sig"])
            elif st["captcha"] and not (pw_done and not cred.success_selector):
                prev = st["sig"]
                st = await self._human(lambda s: s["success"] or s["pw"] or s["user"] or s["otp"] or s["sig"] != prev)
            elif pw_done:
                if cred.success_selector:
                    # No fields left but the success marker is missing: push approval, security key, etc.
                    st = await self._human(lambda s: s["success"] or s["pw"] or s["otp"])
                    continue
                return SIGNED_IN, "login_form_gone"
            elif st["href"].split("?")[0].rstrip("/") != cred.login_url.split("?")[0].rstrip("/"):
                return ALREADY, "redirected_from_login_page"
            else:
                raise _Abort(UNSUPPORTED, "no_login_form_found")
        raise _Abort(UNSUPPORTED, "too_many_steps")

    async def finish(self, keep_tab: bool) -> None:
        """Leave the browser safe to hand back: no secret in the DOM, no broker session attached."""
        try:
            if keep_tab:
                await self._eval(_SCRUB, retries=3)
            else:
                await self.b.call("Target.createTarget", {"url": "about:blank"})
                await self.b.call("Target.closeTarget", {"targetId": self.target}, timeout=5)
        except (CDPError, _Abort):
            pass
        try:
            await self.b.call("Target.detachFromTarget", {"sessionId": self.sid}, timeout=5)
        except CDPError:
            pass


async def clear_site_session(browser: Browser, origins: list[str]) -> None:
    """Remove local cookies and storage for the given origins. Does not log out server-side."""
    hosts = {o.split("://", 1)[1].split(":")[0] for o in origins}
    cookies = (await browser.call("Storage.getCookies"))["cookies"]
    keep = [c for c in cookies if not any(h == c["domain"].lstrip(".") or h.endswith("." + c["domain"].lstrip("."))
                                          for h in hosts)]
    if len(keep) != len(cookies):
        await browser.call("Storage.clearCookies")
        if keep:
            await browser.call("Storage.setCookies", {"cookies": keep})
    for o in origins:
        try:
            await browser.call("Storage.clearDataForOrigin", {"origin": o, "storageTypes": "all"})
        except CDPError:
            pass
