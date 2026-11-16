"""Attacks found in review. Each must leave the password unexposed."""
import asyncio
import base64
import json

import aiohttp

from conftest import AgentCDP
from fakesite import PASSWORD
from gatehouse import login as L


async def _drain(ws, agent, seconds=1.5):
    end = asyncio.get_event_loop().time() + seconds
    while asyncio.get_event_loop().time() < end:
        try:
            f = await ws.receive(timeout=0.5)
        except asyncio.TimeoutError:
            continue
        if f.type != aiohttp.WSMsgType.TEXT:
            break
        agent.events.append(json.loads(f.data))


async def test_page_cannot_fake_the_origin_check(env):
    """A redirect target that patches Array.prototype.includes and JSON.stringify still gets nothing."""
    cid = env.add_account("/redir-evil")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.PERMISSION_REQUIRED, "redirected_to_unapproved_origin")
    assert env.site.received == []


async def test_back_navigation_after_login_reveals_nothing(env):
    cid = env.add_account()
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
    agent = AgentCDP(ws)
    sid = await agent.page()
    assert "Signed in as reader" in await agent.evaluate(sid, "document.body.innerText")
    history = (await agent.call("Page.getNavigationHistory", {}, sid))["result"]["entries"]
    assert len(history) == 1                                  # the login form is not in this tab's past
    await agent.evaluate(sid, "history.go(-1)")
    await asyncio.sleep(1.0)
    values = await agent.evaluate(sid, "[...document.querySelectorAll('input')].map(i => i.value).join('|')")
    assert PASSWORD not in (values or "")
    await ws.close()


async def test_reload_after_direct_post_login_sends_nothing(env):
    cid = env.add_account("/login-direct")
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
    agent = AgentCDP(ws)
    sid = await agent.page()
    await agent.call("Network.enable", {}, sid)
    await agent.call("Page.reload", {}, sid)
    await _drain(ws, agent)
    assert len(env.site.received) == 1                        # the POST was not re-sent
    blob = json.dumps(agent.events)
    for e in agent.events:
        for entry in (e.get("params") or {}).get("request", {}).get("postDataEntries", []):
            blob += base64.b64decode(entry.get("bytes", "")).decode(errors="replace")
    assert PASSWORD not in blob and "Passw0rd" not in blob
    await ws.close()


async def test_repeated_cancel_never_exposes_the_login_tab(env):
    cid = env.add_account("/slow-login")
    env.grant(cid)
    sid = await env.session_id()
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": sid})
    await asyncio.sleep(2.5)                                  # password typed, POST hanging
    cancels = [asyncio.create_task(env.api("/v1/login/cancel", {"request_id": r["request_id"]})) for _ in range(3)]
    seen = []
    for _ in range(3000):
        try:
            ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
        except aiohttp.WSServerHandshakeError:
            await asyncio.sleep(0.002)
            continue
        agent = AgentCDP(ws)
        targets = (await agent.call("Target.getTargets"))["result"]["targetInfos"]
        seen = [t["url"] for t in targets if t["type"] == "page"]
        for t in targets:
            if t["type"] == "page":
                s = await agent.call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True})
                if "result" in s:
                    v = await agent.evaluate(s["result"]["sessionId"],
                                             "[...document.querySelectorAll('input')].map(i => i.value).join('|')")
                    assert PASSWORD not in (v or "")
        await ws.close()
        break
    await asyncio.gather(*cancels)
    assert not any("slow-login" in u for u in seen)
    _, st = await env.api("/v1/login/status", {"request_id": r["request_id"]})
    assert st["status"] == L.CANCELLED


async def test_revoking_an_agent_closes_its_open_browser_connection(env, agent_cdp):
    assert (await agent_cdp.call("Browser.getVersion"))["result"]
    env.store.revoke_agent(env.agent["agent_id"])
    msg = await agent_cdp.ws.receive(timeout=10)
    assert msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.CLOSING)


async def test_submit_button_formaction_to_unapproved_origin(env):
    cid = env.add_account("/formaction")
    env.grant(cid)
    r = await env.login(cid)
    assert (r["status"], r["detail"]) == (L.FAILED, "form_action_mismatch")
    assert env.site.received == []


async def test_page_that_hangs_does_not_hold_the_gate(env):
    cid = env.add_account("/hang-login")
    env.grant(cid)
    start = asyncio.get_event_loop().time()
    r = await env.login(cid, wait=60)
    assert r["status"] in (L.FAILED, L.SIGNED_IN), r
    assert asyncio.get_event_loop().time() - start < 45
    _, b = await env.api("/v1/browser")
    assert b["gate_open"]


async def test_agent_cannot_read_session_cookies(env):
    """Signed in, the agent can use the site but can't copy the HttpOnly session cookie out."""
    cid = env.add_account()
    env.grant(cid)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    ws = await env.http.ws_connect(env.relay_url(), max_msg_size=0)
    agent = AgentCDP(ws)
    for method in ("Storage.getCookies", "Network.getAllCookies"):
        assert "not permitted" in agent_error(await agent.call(method, {}))
    sid = await agent.page()
    for method in ("Network.getCookies", "Network.getAllCookies", "Storage.getCookies"):
        assert "not permitted" in agent_error(await agent.call(method, {}, sid))
    await agent.call("Network.enable", {}, sid)
    await agent.call("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Response"}]}, sid)
    await agent.call("Page.reload", {}, sid)
    end = asyncio.get_event_loop().time() + 3
    while asyncio.get_event_loop().time() < end:              # let paused responses through, keep events
        try:
            f = await ws.receive(timeout=0.5)
        except asyncio.TimeoutError:
            continue
        e = json.loads(f.data)
        agent.events.append(e)
        if e.get("method") == "Fetch.requestPaused":
            await ws.send_json({"id": 9000 + len(agent.events), "sessionId": sid, "method": "Fetch.continueRequest",
                                "params": {"requestId": e["params"]["requestId"]}})
    assert "Signed in as reader" in await agent.evaluate(sid, "document.body.innerText")
    assert any(e.get("method") == "Network.requestWillBeSentExtraInfo" for e in agent.events)
    blob = json.dumps(agent.events).lower()
    assert "session=ok" not in blob and '"set-cookie"' not in blob and '"cookie"' not in blob
    await ws.close()


def agent_error(reply: dict) -> str:
    return (reply.get("error") or {}).get("message", "")
