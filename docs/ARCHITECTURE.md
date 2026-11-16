# Architecture

## Components

| Component | File | Holds secrets? | Role |
|---|---|---|---|
| Vault | `vault.py` | Yes, encrypted at rest | One AES-256-GCM file; key from scrypt over the master passphrase |
| State store | `store.py` | Agent signing keys only | SQLite: agents, grants, approvals, audit, replay nonces, settings |
| Policy | `policy.py` | No | Deny-by-default authorization |
| Browser controller | `cdp.py` | In transit only | Starts Chromium on a debugging **pipe**; relays agent DevTools traffic through a gate |
| Login engine | `login.py` | In transit only | Fills and submits forms in a broker-owned tab |
| Daemon | `server.py` | Vault key in memory | Signed agent API, login orchestration, relay endpoints |
| Human handoff | `handoff.py` | No (streams the login tab as images) | One-time local page for CAPTCHA/MFA while the gate is shut |
| MCP adapter | `mcp_adapter.py` | Agent signing key | stdio MCP server; standard library only |
| macOS deployment | `deploy/macos/` | Generated vault passphrase (service user only) | Service user, LaunchDaemon, private Chrome, `gatehouse-admin`, `gatehouse-connect` |
| CLI | `cli.py` | Prompts only | Management and approval interface |

Core and adapters are separate: nothing in the broker knows about T3 Code or Codex. Any agent that can speak MCP (or sign HTTP requests) and whose browser tool can attach to a DevTools endpoint can integrate.

## Who holds what

- **Credentials:** the daemon process, decrypted per login from `vault.json` using the key held in memory since `gatehouse serve` unlocked it.
- **Browser control during login:** the daemon, exclusively. Chromium is started with `--remote-debugging-pipe`, so the DevTools protocol exists only on two file descriptors the daemon owns. There is no debugging port.
- **Browser control otherwise:** the agent, through `ws://127.0.0.1:<port>/cdp/<token>/devtools/browser`. The daemon relays messages, filters them, and can close the relay.

## The gate

Because every DevTools message passes through the daemon, "prevent agent observation during login" is a property of one code path (`Browser.close_gate`):

1. Close every agent WebSocket and refuse new ones (HTTP 423).
2. Detach every DevTools session the agents created. Session-scoped state goes with them: injected scripts, request interception, auto-attach.
3. Reset browser-level auto-attach and target discovery.
4. Open a new tab for the login, then close all other tabs. Clear service workers and cache storage for the account's websites, and the HTTP cache.
5. Run the login. Every script runs in an isolated JavaScript world of the tab's main frame.
6. Hand back. Open a new tab, on the signed-in URL after success and blank otherwise. Then destroy the login tab: close it, and if it doesn't close, crash its renderer. This cleanup runs to completion even if the login task is cancelled, any number of times.
7. Reopen the gate, but only once the login tab is confirmed gone. If that cannot be confirmed, the whole browser is stopped instead. The next request starts a fresh one on the same profile.

Step 4 is deliberately blunt. Closing every tab discards anything the agent had open; it also discards renderer processes that could share an in-memory cache with the login page.

## Decisions taken (spec "decisions for the implementation project")

| Question | Decision | Why | Revisit when |
|---|---|---|---|
| Name, license | Working name "Gatehouse"; Apache-2.0 | Patent grant suits security software. The name is a placeholder and has not been checked for conflicts | Before publishing |
| Storage backend | Encrypted file (`cryptography`: scrypt + AES-256-GCM), not a dedicated Keychain | Works identically under a dedicated service user with no GUI login, is testable in CI, and gives a real "vault locked" state. A Keychain owned by a daemon user needs its unlock password stored in a file anyway | A Keychain item could hold the *unlock key* for unattended restarts |
| Isolation | Dedicated macOS user for daemon + browser is the supported secure mode; same-user mode is for evaluation | The spec's own premise: same-user processes are not a boundary | A sandboxed helper could replace the second user |
| Browser integration | Broker-controlled Chromium with a gated DevTools relay, not an extension | An extension lives in a browser the agent controls; the relay puts enforcement outside the agent's reach and needs no changes to the agent's browser tool beyond an endpoint URL | Passkey support may need an extension or virtual authenticator |
| Harness integration | `gatehouse-connect` adds two user-scope MCP servers to Claude Code and/or Codex: the Gatehouse adapter and a pinned Playwright MCP (`@playwright/mcp@0.0.84`) on the relay. T3 Code inherits them from the harness it runs | No patching of any harness. Playwright MCP reconnects by itself after the gate reopens (tested) | If a T3 version does not pass harness MCP config through, add the printed definitions in T3 |
| Approval UI | Local CLI (`gatehouse-admin`, behind sudo), plus a local page for human verification only | The sudo password is the one thing agents running as the user lack | Notifications when an agent is waiting on you |
| Browser for the service | Private Chrome for Testing in `/opt/gatehouse`, headless, weekly update; fallback is a strictly signature-checked copy of the installed Chrome | The user's Chrome is writable by the user (and so by agents) and must not run as the broker | n/a |
| Backup / recovery | Back up `vault.json` (already encrypted) with the passphrase stored elsewhere. No recovery without the passphrase. `state.db` is replaceable: losing it loses grants and history, not credentials | Simple and honest | An explicit `export`/`rotate-passphrase` command |
| TOTP in MVP | Yes | Small, tested against RFC 6238 vectors | n/a |

## Status against the MVP list

Built and tested: dedicated encrypted store; manual entry; selective CSV import (generic + Apple Passwords layout); persistent agent/account/origin grants with four durations; one controlled Chromium per agent; authenticated API with replay protection; MCP adapter; password, multi-step and TOTP login; session reuse; audit; revocation; global disable; human-verification handoff; cancellation; failure limit.

Not done:

- **Installer as root.** `deploy/macos/install.sh` has been exercised in a same-user simulation (all commands, a real broker, Claude Code end to end), not yet as root with the `_gatehouse` user.
- **Goodreads workflow.** Needs the M1, a real account entered through `gatehouse account add`, and probably a `--pre-click` selector for the "Sign in with email" button. Amazon-backed sign-in commonly shows a CAPTCHA to automated browsers; expect the human handoff.
- **Local web UI.** Management is CLI-only.
- **Unlock while running.** The vault is unlocked when `serve` starts; locking means stopping the daemon.
- **Website-side session revocation.** Not implemented for any site.
- **Direct Apple Passwords API import, passkeys, federated sign-in, iframe login forms.** Out of MVP scope.
- **Downloads and file uploads through the relay.** Blocked; see threat model.
