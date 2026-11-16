# Threat model

## What is protected

1. **Credential values**: passwords and TOTP secrets.
2. **Scope of use**: a credential is used only for the agent, account and websites in a live grant.
3. **Revocation**: a revoked grant or agent cannot cause another use.

Not protected: the contents of an account once an agent is signed in to it.

## Adversaries considered

- **A misbehaving or prompt-injected agent** with: the MCP tools, its own signing key, a DevTools connection through the relay, and (in the supported deployment) a shell as a *different* macOS user from the broker.
- **A web page**, including the login page of an approved site and any page the agent visits, trying to redirect a login, widen a grant, or reach the broker on localhost.
- **Imported data** carrying instructions, terminal escape sequences or hostile URLs.

Not considered: root or kernel compromise, a malicious Chromium build, physical access, a compromised website that legitimately receives the password.

## Deployment modes

| | Dedicated broker user (supported) | Same user as the agent (evaluation only) |
|---|---|---|
| Agent reads `vault.json` | No (file permissions) | Yes, but encrypted |
| Agent reads the passphrase file, if one is used | No | **Yes** |
| Agent reads daemon memory / attaches a debugger | No | **Possible** |
| Agent reads browser profile (cookies) on disk | No | **Yes** (`--use-mock-keychain` means cookies are not protected by the login Keychain) |
| Agent opens Chromium's DevTools directly | No (pipe only) | Not through a port, but can debug the process |

In same-user mode do not claim the agent cannot obtain passwords.

## What the agent can and cannot do

Verified by tests in `tests/test_login_flow.py` and `tests/test_api.py` (Linux, Chrome 153):

| Channel | During protected login | Otherwise |
|---|---|---|
| MCP / HTTP API | Status words only | Authorized account metadata (name, username, websites); never a secret. No endpoint returns one |
| DevTools relay | Disconnected; reconnect refused | Full control of pages, subject to the filter below |
| Scripts injected earlier | Removed with the agent's sessions; the login runs in a new tab | n/a |
| Request interception set earlier | Removed with the agent's sessions | n/a |
| Screenshots, DOM evaluation | Impossible (no connection) | Allowed; the password field is blanked before handback |
| Service worker planted on the site | Cleared for the account's websites before login | n/a |
| Broker files | No access in dedicated-user mode | No access in dedicated-user mode |

Relay filter (`cdp.py`): browser-level commands are allowlisted; `Tracing`, `Extensions`, `SystemInfo`, `Tethering`, certificate-error overrides, CSP bypass, `DOM.setFileInputFiles`, `Browser.close` and attaching to the browser target are refused; navigation commands accept only `http(s)` and `about:blank`.

## Rules that stop a grant from growing

- Websites are exact origins: scheme, host and port. No wildcards, no subdomain matching.
- A use needs the origin on the account **and** on the grant.
- The check runs in the page, in the same script that fills the field: top-level document on an allowed origin, form `action` on an allowed origin. A redirect to another origin ends the attempt with `permission_required` before anything is typed, and queues a request for you. Nothing on a page can approve it.
- Import never approves a website and never creates a grant.
- Requests are HMAC-signed over method, path, timestamp, nonce and body; nonces are single-use. The relay and API reject any request carrying an `Origin` header or an unexpected `Host`, which blocks web pages and DNS rebinding.

## Residual risks

1. **The session is the prize.** A signed-in agent can read session cookies through DevTools and act as you on that site for as long as the site honours them. On sites that allow it without re-authentication, that includes changing the password or email. Mitigate with narrow grants, sites' own session controls, and action-level approval in the agent harness.
2. **Revocation is not logout.** Revoking a grant or agent does not end website sessions already established. `logout` removes local cookies and storage only.
3. **The relay filter is partly a denylist.** Page-level DevTools commands not on the list are forwarded. A Chromium command that reads local files or persists across the gate, and that we failed to list, would be a hole. Dedicated-user mode limits what such a hole exposes to the broker user's files.
4. **Persistent browser state.** Cookies, local storage and permissions the agent set before a login persist. The broker clears service workers, cache storage and the HTTP cache for the account's sites; other persistent mechanisms may exist.
5. **The website sees the password.** So does any script the site loads. That is inherent in password login.
6. **Heuristic success detection.** Without a `--success-selector`, "the password field is gone" counts as signed in. A page asking for push approval can look the same. Set a success selector for accounts that matter.
7. **Heuristic field detection.** An unusual page could present a non-login field that looks like a username field; the username (not the password) could be typed into it. Password fields are matched by `type=password` only.
8. **Human verification needs a visible browser.** The gate stays shut while you solve a challenge, up to a timeout. In headless mode challenges cannot be completed.
9. **Signing keys at rest.** Agent signing keys are stored in `state.db` in clear (the daemon needs them to verify). Anyone who can read that file can impersonate agents, within those agents' grants.
10. **Memory.** Python cannot reliably wipe strings. Decrypted credentials exist in daemon memory during a login and until garbage-collected; the vault key lives for the daemon's lifetime.
11. **Chromium's own password manager** is disabled by preference and flags, not by policy. If it offered to save a password, a headful user could accept.

## Authorization after login

A grant covers signing in. It does not authorize actions inside the account, and the broker does not see or mediate them. Existing agreements in the agent harness still apply: sending email needs approval of exact recipients and content, purchases follow their own authorization, routine pre-authorized actions proceed. Gatehouse neither weakens nor enforces these.
