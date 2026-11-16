"""Agent API: authentication, replay protection and permission edges, against a live broker."""
import asyncio
import json
import time

from gatehouse import login as L
from gatehouse.client import BrokerClient
from gatehouse.mcp_adapter import Adapter


async def raw(env, path, body: bytes, headers: dict):
    async with env.http.post(f"http://127.0.0.1:{env.port}{path}", data=body, headers=headers) as r:
        return r.status, await r.json()


async def test_unsigned_wrong_key_and_stale_requests_rejected(env):
    assert (await raw(env, "/v1/accounts", b"{}", {}))[0] == 401
    bad = BrokerClient(env.client.url, env.agent["agent_id"], "wrong-key")
    assert (await env.api("/v1/accounts", client=bad))[0] == 401
    old = env.client.headers("/v1/accounts", b"{}", ts=str(time.time() - 3600))
    assert (await raw(env, "/v1/accounts", b"{}", old))[0] == 401
    ghost = BrokerClient(env.client.url, "agt_doesnotexist", env.agent["sign_key"])
    assert (await env.api("/v1/accounts", client=ghost))[0] == 401


async def test_replayed_and_tampered_requests_rejected(env):
    cid = env.add_account()
    env.grant(cid)
    sid = await env.session_id()
    body = json.dumps({"account_id": cid, "browser_session_id": sid}).encode()
    headers = env.client.headers("/v1/login", body)
    status, first = await raw(env, "/v1/login", body, headers)
    assert status == 200 and first["request_id"]
    assert (await raw(env, "/v1/login", body, headers))[0] == 401                 # exact replay
    assert (await raw(env, "/v1/logout", body, headers))[0] == 401                # same signature, other endpoint
    tampered = env.client.headers("/v1/login", body)
    assert (await raw(env, "/v1/login", body.replace(cid.encode(), b"x" * 16), tampered))[0] == 401
    assert any(r["result"] == "replay" for r in env.store.audit_rows(100))


async def test_listing_shows_only_authorized_metadata(env):
    a = env.add_account()
    env.add_account()                                   # second account, no grant
    env.grant(a)
    _, r = await env.api("/v1/accounts")
    assert [x["account_id"] for x in r["accounts"]] == [a]
    assert set(r["accounts"][0]) == {"account_id", "name", "username", "origins", "has_totp"}


async def test_unapproved_agent_and_unknown_account_look_the_same(env):
    cid = env.add_account()
    sid = await env.session_id()
    _, no_grant = await env.api("/v1/login", {"account_id": cid, "browser_session_id": sid})
    _, unknown = await env.api("/v1/login", {"account_id": "0" * 16, "browser_session_id": sid})
    assert (no_grant["status"], no_grant["detail"]) == (unknown["status"], unknown["detail"]) == (L.PERMISSION_DENIED, "not_authorized")
    assert env.site.received == []


async def test_expired_once_and_revoked_grants(env):
    cid = env.add_account()
    g = env.grant(cid, kind="until", expires_at=time.time() + 1.5)
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    await asyncio.sleep(1.6)
    r = await env.login(cid)
    assert r["status"] == L.PERMISSION_REQUIRED                                  # expired: user is asked, nothing is typed
    assert len(env.store.approvals()) == 1
    env.store.revoke_grant(g)
    once = env.grant(cid, kind="once")
    await env.api("/v1/logout", {"account_id": cid, "browser_session_id": await env.session_id()})
    assert (await env.login(cid))["status"] == L.SIGNED_IN
    assert (await env.login(cid))["status"] == L.PERMISSION_REQUIRED             # single use is spent
    env.store.revoke_grant(once)
    assert (await env.login(cid))["status"] == L.PERMISSION_DENIED               # everything revoked
    assert env.site.posts == 2


async def test_revocation_and_global_disable_take_effect_immediately(env):
    cid = env.add_account()
    g = env.grant(cid)
    env.store.set_setting("logins_disabled", "1")
    assert (await env.login(cid))["detail"] == "logins_disabled"
    env.store.set_setting("logins_disabled", "0")
    env.store.revoke_grant(g)
    assert (await env.login(cid))["status"] == L.PERMISSION_DENIED
    assert env.site.received == []


async def test_session_grant_ends_with_the_broker_session(env):
    cid = env.add_account()
    env.grant(cid, kind="session", boot_id="some-earlier-boot")
    assert (await env.login(cid))["status"] == L.PERMISSION_REQUIRED
    env.grant(cid, kind="session", boot_id=env.broker.boot_id)
    assert (await env.login(cid))["status"] == L.SIGNED_IN


async def test_agents_are_isolated_from_each_other(env):
    cid = env.add_account()
    env.grant(cid)
    other = env.store.add_agent("other")
    other_client = BrokerClient(env.client.url, other["agent_id"], other["sign_key"])
    sid = await env.session_id()
    other_sid = await env.session_id(other_client)
    assert sid != other_sid                                                       # separate browser profiles
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": sid}, other_client)
    assert r["status"] == L.PERMISSION_DENIED
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": other_sid})
    assert r["detail"] == "unknown_browser_session"                               # cannot target another agent's browser
    done = await env.login(cid)
    _, r = await env.api("/v1/login/status", {"request_id": done["request_id"]}, other_client)
    assert r["status"] == "unknown_request"


async def test_vault_locked(env):
    cid = env.add_account()
    env.grant(cid)
    env.broker.key = None
    assert (await env.login(cid))["status"] == L.VAULT_LOCKED
    assert (await env.api("/v1/accounts"))[1]["status"] == L.VAULT_LOCKED


async def test_cancel(env):
    cid = env.add_account("/captcha-login")
    env.grant(cid)
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": await env.session_id()})
    await asyncio.sleep(2)
    _, r = await env.api("/v1/login/cancel", {"request_id": r["request_id"]})
    assert r["status"] == L.CANCELLED
    assert env.broker.browsers[env.agent["agent_id"]].gate_open                   # browser handed back
    assert env.site.received == []


async def test_mcp_adapter_end_to_end(env):
    cid = env.add_account()
    env.grant(cid)
    adapter = Adapter(env.client)

    def rpc(method, params=None, mid=1):
        return adapter.handle({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})

    assert (await asyncio.to_thread(rpc, "initialize", {"protocolVersion": "2025-06-18"}))["result"]["serverInfo"]["name"] == "gatehouse"
    tools = (await asyncio.to_thread(rpc, "tools/list"))["result"]["tools"]
    assert {t["name"] for t in tools} == {"list_authorized_accounts", "request_login", "get_login_status", "logout"}
    assert not any("password" in json.dumps(t["inputSchema"]) for t in tools)     # no way to ask for a secret
    listed = await asyncio.to_thread(rpc, "tools/call", {"name": "list_authorized_accounts", "arguments": {}})
    assert cid in listed["result"]["content"][0]["text"]
    out = await asyncio.to_thread(rpc, "tools/call", {"name": "request_login", "arguments": {"account_id": cid}})
    assert json.loads(out["result"]["content"][0]["text"])["status"] == L.SIGNED_IN
    assert adapter.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
