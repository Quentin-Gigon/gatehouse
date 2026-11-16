"""Safari sign-in: the broker hands the login only to the Gatehouse app's authenticated channel."""
import asyncio

import aiohttp

from fakesite import PASSWORD
from gatehouse import login as L


async def register_filler(env) -> str:
    token = env.store.add_admin_token(600)
    async with env.http.post(f"http://127.0.0.1:{env.port}/admin/filler/register",
                             headers={"Authorization": f"Bearer {token}"}, json={}) as r:
        return (await r.json())["filler_key"]


async def connect_filler(env, key):
    return await env.http.ws_connect(f"ws://127.0.0.1:{env.port}/filler/ws", headers={"Authorization": f"Bearer {key}"})


def safari_account(env, allow=True) -> str:
    return env.add_account(allow_safari=allow)


async def status(env, r, wait=10):
    end = asyncio.get_event_loop().time() + wait
    while r.get("request_id") and r["status"] == L.PENDING and asyncio.get_event_loop().time() < end:
        await asyncio.sleep(0.1)
        _, r = await env.api("/v1/login/status", {"request_id": r["request_id"]})
    return r


async def test_filler_channel_needs_the_registered_key(env):
    for headers in ({}, {"Authorization": "Bearer guess"}):
        try:
            await env.http.ws_connect(f"ws://127.0.0.1:{env.port}/filler/ws", headers=headers)
            raise AssertionError("connected without the key")
        except aiohttp.WSServerHandshakeError as e:
            assert e.status == 403
    old = await register_filler(env)
    new = await register_filler(env)                      # re-registering retires the old key
    try:
        await connect_filler(env, old)
        raise AssertionError("old key still works")
    except aiohttp.WSServerHandshakeError as e:
        assert e.status == 403
    ws = await connect_filler(env, new)
    await ws.close()


async def test_safari_needs_the_per_account_switch_and_the_app(env):
    cid = safari_account(env, allow=False)
    env.grant(cid)
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    assert (r["status"], r["detail"]) == (L.PERMISSION_DENIED, "safari_sign_in_not_allowed_for_this_account_ask_the_user")
    cid = safari_account(env)
    env.grant(cid)
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    assert r["detail"] == "gatehouse_app_not_running_ask_the_user_to_open_it"


async def test_safari_needs_a_grant(env):
    cid = safari_account(env)
    ws = await connect_filler(env, await register_filler(env))
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    assert r["status"] == L.PERMISSION_DENIED
    await ws.close()


async def test_safari_sign_in_round_trip(env):
    cid = safari_account(env)
    env.grant(cid)
    ws = await connect_filler(env, await register_filler(env))
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    assert r["status"] == L.PENDING
    fill = await ws.receive_json(timeout=5)
    assert fill["type"] == "fill" and fill["password"] == PASSWORD and fill["origins"] == [env.origin]
    await ws.send_json({"type": "result", "request_id": fill["request_id"], "status": L.SIGNED_IN, "detail": "safari"})
    r = await status(env, r)
    assert r["status"] == L.SIGNED_IN
    assert "password" not in r and PASSWORD not in str(r)
    await ws.close()


async def test_rejected_password_counts_as_a_failure_and_disconnect_fails_cleanly(env):
    cid = safari_account(env)
    env.grant(cid)
    ws = await connect_filler(env, await register_filler(env))
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    fill = await ws.receive_json(timeout=5)
    await ws.send_json({"type": "result", "request_id": fill["request_id"], "status": L.FAILED, "detail": "credentials_rejected"})
    assert (await status(env, r))["status"] == L.FAILED
    assert env.store.failures(cid) == 1

    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    await ws.receive_json(timeout=5)
    await ws.close()                                      # the app quits mid-sign-in
    r = await status(env, r)
    assert (r["status"], r["detail"]) == (L.FAILED, "gatehouse_app_disconnected")


async def test_a_made_up_status_from_the_app_is_not_trusted(env):
    cid = safari_account(env)
    env.grant(cid)
    ws = await connect_filler(env, await register_filler(env))
    _, r = await env.api("/v1/safari/login", {"account_id": cid})
    fill = await ws.receive_json(timeout=5)
    await ws.send_json({"type": "result", "request_id": fill["request_id"], "status": "granted_everything"})
    assert (await status(env, r))["status"] == L.FAILED
    await ws.close()
