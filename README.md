# Gatehouse

A local, open-source credential broker for AI agents. You choose which agent may sign in to which account on which website and for how long. The broker types the credentials into a browser it owns; the agent gets the signed-in session, not the password.

> **Status: 0.1.0, pre-release.** Developed and tested on Linux with Chrome 153. The macOS deployment described in `docs/DEPLOYMENT.md` has **not yet been run on a Mac**. Gatehouse is an independent project and is not affiliated with 1Password or any other vendor.

## What it does

- Stores only the accounts you add or individually select from a CSV export, in an encrypted vault.
- Denies by default. A grant names one agent, one account, the approved websites, and a duration: once, this broker session, until a date, or until revoked.
- Signs in for the agent inside a browser only the broker can control. While it types, the agent's browser connection is closed.
- Within a grant, repeat logins need no prompt. Outside it, the request waits for you.
- Hands CAPTCHA, push approval and other challenges to you, then lets the agent continue.
- Keeps an activity history with identifiers and outcomes, never values.
- No telemetry, no hosted service, no subscription.

## Quick start

```sh
python -m pip install -e .
gatehouse init                       # choose the vault passphrase
gatehouse serve                      # terminal 1: unlocks the vault and runs the broker

gatehouse account add                # terminal 2: prompts for name, username, password, sign-in page
gatehouse agent add codex --write-config ~/.config/gatehouse/agent-codex.json
gatehouse grant add --agent codex --account "My account" --for forever
```

`agent add` prints the browser endpoint for the agent's browser tool and writes the API config for the MCP adapter. Wiring for Codex is in `docs/DEPLOYMENT.md`.

Day to day:

```sh
gatehouse approvals                  # requests waiting for you
gatehouse approve apr_... --for 2026-12-31
gatehouse grant list --names
gatehouse grant revoke grt_...
gatehouse audit
gatehouse logins disable             # stop all new logins at once
gatehouse import ~/Downloads/Passwords.csv
```

## How a login works

1. The agent calls `request_login(account_id)`.
2. The broker checks the agent's signature, the grant, the account's approved websites, the global switch and the failure counter.
3. It disconnects the agent from the browser, closes the agent's tabs, and opens a fresh tab on the account's sign-in page.
4. Before each field is filled, a script checks in the same step that the page is on an approved website and that the form posts to one.
5. It submits once. Wrong password means `login_failed`; after two rejections the account is blocked until you run `gatehouse account unblock`.
6. On success the agent reconnects and finds the signed-in tab.

## What it does not do

- It does not make an agent harmless inside an account. A signed-in agent can do what the website lets that session do. Approval of individual actions (sending email, purchases) is the agent harness's job; see `docs/THREAT_MODEL.md`.
- Revoking a grant stops future use of the credential. It does not end a website session the agent already holds; `logout` clears the local session only.
- It does not bypass CAPTCHA or MFA, and does not handle passkeys, "Sign in with Google/Apple", or login forms inside iframes.
- Run as your own macOS user, it is **not** a strong boundary against an agent with an unrestricted shell. Use a dedicated user (`docs/DEPLOYMENT.md`).

## Documentation

- `docs/ARCHITECTURE.md`: components, decisions, what is and is not built
- `docs/THREAT_MODEL.md`: what the agent can and cannot see, residual risks
- `docs/API.md`: HTTP API, MCP tools, browser relay
- `docs/IMPORT.md`: CSV formats and import behaviour
- `docs/DEPLOYMENT.md`: macOS setup, Codex/T3 wiring, backup, upgrade
- `SECURITY.md`: reporting vulnerabilities

## Tests

```sh
python -m pip install -e ".[dev]"
python -m pytest
```

The integration tests start a real Chromium and a synthetic login site on localhost. All credentials in the repository are fake.

## License

Apache-2.0.
