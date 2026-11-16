"""Completion must not destroy an in-flight federated login."""
import asyncio
from types import SimpleNamespace

import pytest

from gatehouse import login as L


def state(origin, **changes):
    return dict(dict(origin=origin, href=origin + '/page', sig=origin, ready='complete',
                pw=0, otp=0, captcha=False, success=False, sso=False), **changes)


def run_for(service='https://service.test', timeout=2):
    return L.LoginRun(None, SimpleNamespace(login_url=service+'/login', success_selector=None),
                      [service, 'https://idp.test'], L.Timeouts(navigation=timeout, settle=0.01))


async def test_waits_through_delayed_saml_post():
    run = run_for()
    initial = state('https://idp.test', sso=True)
    started = asyncio.get_running_loop().time()
    async def next_state():
        if asyncio.get_running_loop().time() - started < 0.5:
            return initial
        return state('https://service.test')
    run._state = next_state
    result = await run._wait_completion(initial)
    assert result['origin'] == 'https://service.test'
    assert asyncio.get_running_loop().time() - started >= 1.5


async def test_stalled_identity_provider_is_not_success():
    run = run_for(timeout=0.1)
    initial = state('https://idp.test')
    async def next_state():
        return initial
    run._state = next_state
    with pytest.raises(L._Abort) as exc:
        await run._wait_completion(initial)
    assert (exc.value.status, exc.value.detail) == (L.UNSUPPORTED, 'sso_completion_timeout')


async def test_unapproved_redirect_after_password_still_requires_permission():
    run = run_for()
    with pytest.raises(L._Abort) as exc:
        await run._wait_completion(state('https://unapproved.test'))
    assert exc.value.status == L.PERMISSION_REQUIRED
    assert run.unapproved_origin == 'https://unapproved.test'
