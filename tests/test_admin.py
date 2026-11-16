"""The admin API behind the app: locked without a token, never reveals secrets."""
import json
import time

from fakesite import PASSWORD, USER
from gatehouse import login as L

CSV = ("name,url,username,password,totp,notes\n"
       "Synthetic Books,https://books.example.test/login,reader@example.test,synthetic-Passw0rd!-not-real,,\n"
       "Synthetic Mail,https://mail.example.test,reader@example.test,another-synthetic-secret,JBSWY3DPEHPK3PXP,\n")


async def admin(env, path, payload=None, token=None, headers=None):
    h = {"Authorization": f"Bearer {token}"} if token else {}
    async with env.http.post(f"http://127.0.0.1:{env.port}/admin/{path}", json=payload or {},
                             headers={**h, **(headers or {})}) as r:
        return r.status, await r.json()


async def test_admin_api_is_locked_without_a_token(env):
    assert (await admin(env, "overview"))[0] == 401
    assert (await admin(env, "overview", token="guess"))[0] == 401
    status, _ = await admin(env, "account/add", {"name": "x", "username": "u", "password": "p",
                                                  "login_url": env.origin}, token="guess")
    assert status == 401


async def test_admin_api_refuses_browser_pages(env):
    """A web page can't use an unlocked app's token: requests carrying an Origin are refused."""
    token = env.store.add_admin_token(60)
    status, _ = await admin(env, "overview", token=token, headers={"Origin": "https://evil.example"})
    assert status == 403


async def test_token_expires_when_idle_and_on_lock(env, monkeypatch):
    from gatehouse import server
    token = env.store.add_admin_token(3600)
    assert (await admin(env, "overview", token=token))[0] == 200
    monkeypatch.setattr(server, "ADMIN_IDLE", 0.0)
    assert (await admin(env, "overview", token=token))[0] == 401
    monkeypatch.setattr(server, "ADMIN_IDLE", 900.0)
    token = env.store.add_admin_token(3600)
    assert (await admin(env, "lock", token=token))[0] == 200
    assert (await admin(env, "overview", token=token))[0] == 401
    token = env.store.add_admin_token(0.0)                   # past its maximum age
    time.sleep(0.01)
    assert (await admin(env, "overview", token=token))[0] == 401


async def test_add_grant_and_sign_in_through_the_admin_api(env):
    token = env.store.add_admin_token(600)
    status, r = await admin(env, "account/add", {"name": "Books", "username": USER, "password": PASSWORD,
                                                  "login_url": env.origin + "/login"}, token)
    assert status == 200, r
    cid = r["account_id"]
    status, r = await admin(env, "access", {"agent_id": env.agent["agent_id"], "account_id": cid,
                                            "allowed": True, "duration": "forever"}, token)
    assert status == 200 and r["grant_id"], r
    assert (await env.login(cid))["status"] == L.SIGNED_IN

    _, ov = await admin(env, "overview", token=token)
    blob = json.dumps(ov)
    assert PASSWORD not in blob and "password" not in [k for a in ov["accounts"] for k in a]
    assert [g["state"] for g in ov["grants"]] == ["active"]

    _, r = await admin(env, "access", {"agent_id": env.agent["agent_id"], "account_id": cid, "allowed": False}, token)
    _, ov = await admin(env, "overview", token=token)
    assert [g["state"] for g in ov["grants"]] == ["revoked"]
    _, r = await env.api("/v1/login", {"account_id": cid, "browser_session_id": await env.session_id()})
    assert r["status"] == L.PERMISSION_DENIED


async def test_import_preview_hides_passwords_and_apply_approves_ticked_sites(env):
    token = env.store.add_admin_token(600)
    status, r = await admin(env, "import/preview", {"csv": CSV}, token)
    assert status == 200
    assert "synthetic-Passw0rd" not in json.dumps(r) and "another-synthetic" not in json.dumps(r)
    assert [e["name"] for e in r["entries"]] == ["Synthetic Books", "Synthetic Mail"]
    status, r = await admin(env, "import/apply", {"csv": CSV, "selected": [2]}, token)
    assert status == 200 and r["imported"] == ["Synthetic Mail"], r
    _, ov = await admin(env, "overview", token=token)
    acct = ov["accounts"][0]
    assert acct["origins"] == ["https://mail.example.test"] and acct["has_totp"]
    assert acct["login_url"] == "https://mail.example.test"


async def test_connect_agent_issues_and_rotates_keys(env):
    token = env.store.add_admin_token(600)
    _, a = await admin(env, "agent/connect", {"name": "codex"}, token)
    _, b = await admin(env, "agent/connect", {"name": "codex"}, token)
    assert a["agent_id"] == b["agent_id"] and a["sign_key"] != b["sign_key"]
    assert (await admin(env, "agent/connect", {"name": "../bad"}, token))[0] == 400


async def test_attention_needs_no_token_and_reveals_no_secrets(env):
    async with env.http.get(f"http://127.0.0.1:{env.port}/v1/attention") as r:
        body = await r.json()
    assert r.status == 200 and body["handoffs"] == [] and body["approvals"] == 0
