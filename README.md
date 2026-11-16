# Gatehouse

A local, open-source credential broker for AI agents. You choose which agent may sign in to which account on which website and for how long. The broker types the credentials into a browser it owns; the agent gets the signed-in session, not the password.

> **Status: 0.2.0.** Runs on macOS as a background service under its own hidden user (`deploy/macos`). Tested with Chrome 157 on macOS 27 and with Claude Code driving it through MCP. It is not yet proven against many real websites, so expect to tune a few with per-site settings. Gatehouse is an independent project and is not affiliated with 1Password or any other vendor.

## What it does

- Stores only the accounts you add or individually select from a CSV export, in an encrypted vault.
- Denies by default. A grant names one agent, one account, the approved websites, and a duration: once, this broker session, until a date, or until revoked.
- Signs in for the agent inside a browser only the broker can control. While it types, the agent's browser connection is closed.
- Within a grant, repeat logins need no prompt. Outside it, the request waits for you.
- Hands CAPTCHA, push approval and other challenges to you, then lets the agent continue.
- Keeps an activity history with identifiers and outcomes, never values.
- No telemetry, no hosted service, no subscription.

## Quick start (macOS)

```sh
sudo deploy/macos/install.sh                  # service user, private Python + Chrome, vault, LaunchDaemon
gatehouse-admin account add                   # name, username, hidden password, sign-in page
gatehouse-connect claude-code                 # agent identity + MCP tools for Claude Code
gatehouse-connect codex                       # same for Codex (T3 Code uses these configs)
gatehouse-admin grant add --agent claude-code --account "My account" --for forever
```

Then ask the agent to do something on that site. It signs in with the `gatehouse` tools and works in the `gatehouse-browser` tools. Full guide: `docs/DEPLOYMENT.md`.

Day to day:

```sh
gatehouse-admin handoff                       # solve a CAPTCHA / enter a code an agent is waiting on
gatehouse-admin approvals                     # requests waiting for you
gatehouse-admin approve apr_... --for 2026-12-31
gatehouse-admin grant list --names
gatehouse-admin grant revoke grt_...
gatehouse-admin audit
gatehouse-admin logins disable                # stop all new logins at once
gatehouse-admin import ~/Downloads/Passwords.csv
```

To try it without installing anything system-wide, run `./run-demo.sh`, which uses a local fake site and throwaway state.

## How a login works

1. The agent calls `request_login(account_id)`.
2. The broker checks the agent's signature, the grant, the account's approved websites, the global switch and the failure counter.
3. It disconnects the agent from the browser, closes the agent's tabs, and opens a fresh tab on the account's sign-in page.
4. Before each field is filled, a script checks in the same step that the page is on an approved website and that the form posts to one. The script runs in an isolated JavaScript world that the page cannot tamper with, and the page's address is taken from the browser, not from the page.
5. It submits once. Wrong password means `login_failed`; after two rejections the account is blocked until you run `gatehouse-admin account unblock`.
6. If the site shows a CAPTCHA or asks for a code it cannot type itself, it waits for you (`gatehouse-admin handoff`).
7. On success it opens the signed-in page in a new tab and destroys the login tab, so its history, which holds the filled form, cannot be revisited. The agent reconnects and continues there.

## What it does not do

- It does not make an agent harmless inside an account. A signed-in agent can do what the website lets that session do. Approval of individual actions (sending email, purchases) is the agent harness's job; see `docs/THREAT_MODEL.md`.
- Revoking a grant stops future use of the credential. It does not end a website session the agent already holds; `logout` clears the local session only.
- It does not bypass CAPTCHA or MFA (you solve those through `gatehouse-admin handoff`), and does not handle passkeys, "Sign in with Google/Apple", or login forms inside iframes.
- Run as your own macOS user (development mode), it is **not** a strong boundary against an agent with an unrestricted shell. The macOS installer runs it as a separate user for that reason.

## Documentation

- `docs/ARCHITECTURE.md`: components, decisions, what is and is not built
- `docs/THREAT_MODEL.md`: what the agent can and cannot see, residual risks
- `docs/API.md`: HTTP API, MCP tools, browser relay
- `docs/IMPORT.md`: CSV formats and import behaviour
- `docs/DEPLOYMENT.md`: macOS install, connecting Claude Code / Codex / T3, CAPTCHA handoff, backup, upgrade
- `SECURITY.md`: reporting vulnerabilities

## Tests

```sh
uv venv --python 3.12 && uv pip install -e ".[dev]"
.venv/bin/python -m pytest
```

The integration tests start a real Chromium and a synthetic login site on localhost. `tests/test_attacks.py` holds the attacks found in review (hostile pages, back/reload after login, cancel races); each must fail to expose the password. All credentials in the repository are fake.

## License

Apache-2.0.
