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
| MCP adapter | `mcp_adapter.py` | Agent signing key | stdio MCP server; standard library only |
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
5. Run the login. On success, blank any password field left in the DOM and detach. On any other outcome, close the login tab.
6. Reopen the gate.

Step 4 is deliberately blunt. Closing every tab discards anything the agent had open; it also discards renderer processes that could share an in-memory cache with the login page.

## Decisions taken (spec "decisions for the implementation project")

| Question | Decision | Why | Revisit when |
|---|---|---|---|
| Name, license | Working name "Gatehouse"; Apache-2.0 | Patent grant suits security software. The name is a placeholder and has not been checked for conflicts | Before publishing |
| Storage backend | Encrypted file (`cryptography`: scrypt + AES-256-GCM), not a dedicated Keychain | Works identically under a dedicated service user with no GUI login, is testable in CI, and gives a real "vault locked" state. A Keychain owned by a daemon user needs its unlock password stored in a file anyway | A Keychain item could hold the *unlock key* for unattended restarts |
| Isolation | Dedicated macOS user for daemon + browser is the supported secure mode; same-user mode is for evaluation | The spec's own premise: same-user processes are not a boundary | A sandboxed helper could replace the second user |
| Browser integration | Broker-controlled Chromium with a gated DevTools relay, not an extension | An extension lives in a browser the agent controls; the relay puts enforcement outside the agent's reach and needs no changes to the agent's browser tool beyond an endpoint URL | Passkey support may need an extension or virtual authenticator |
| T3 integration | Via Codex MCP config: Gatehouse MCP + a CDP-capable browser MCP pointed at the relay. T3's built-in browser tool and secret-request storage are not used | No patching of T3; no reliance on its plaintext temp files | **Unverified on the M1**: needs a check that T3 Code passes Codex MCP config through |
| Approval UI | Local CLI | Smallest thing that is correct | A local web UI and notifications are the obvious next step |
| Backup / recovery | Back up `vault.json` (already encrypted) with the passphrase stored elsewhere. No recovery without the passphrase. `state.db` is replaceable: losing it loses grants and history, not credentials | Simple and honest | An explicit `export`/`rotate-passphrase` command |
| TOTP in MVP | Yes | Small, tested against RFC 6238 vectors | n/a |

## Status against the MVP list

Built and tested: dedicated encrypted store; manual entry; selective CSV import (generic + Apple Passwords layout); persistent agent/account/origin grants with four durations; one controlled Chromium per agent; authenticated API with replay protection; MCP adapter; password, multi-step and TOTP login; session reuse; audit; revocation; global disable; human-verification handoff; cancellation; failure limit.

Not done:

- **macOS run.** Nothing here has executed on macOS yet. CI is configured for an Apple Silicon runner but has not run.
- **Goodreads workflow.** Needs the M1, a real account entered through `gatehouse account add`, and probably a `--pre-click` selector for the "Sign in with email" button. Amazon-backed sign-in commonly shows a CAPTCHA to automated browsers; expect the human handoff.
- **Local web UI.** Management is CLI-only.
- **Unlock while running.** The vault is unlocked when `serve` starts; locking means stopping the daemon.
- **Website-side session revocation.** Not implemented for any site.
- **Direct Apple Passwords API import, passkeys, federated sign-in, iframe login forms.** Out of MVP scope.
- **Downloads and file uploads through the relay.** Blocked; see threat model.
