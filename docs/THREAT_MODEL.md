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

In both modes, every agent runs as you. So one agent can read another agent's key file in `~/.config/gatehouse/` and act as that agent within that agent's grants. Agent identities separate grants and history; they are not a boundary between agents.

## What the agent can and cannot do

Verified by tests in `tests/test_login_flow.py`, `tests/test_attacks.py` and `tests/test_api.py` (macOS 27, Chrome 157):

| Channel | During protected login | Otherwise |
|---|---|---|
| MCP / HTTP API | Status words only | Authorized account metadata (name, username, websites); never a secret. No endpoint returns one |
| DevTools relay | Disconnected; reconnect refused | Full control of pages, subject to the filter below |
| Scripts injected earlier | Removed with the agent's sessions; the login runs in a new tab | n/a |
| Request interception set earlier | Removed with the agent's sessions | n/a |
| Screenshots, DOM evaluation | Impossible (no connection) | Allowed; the password field is blanked before handback |
| Service worker planted on the site | Cleared for the account's websites before login | n/a |
| Broker files | No access in dedicated-user mode | No access in dedicated-user mode |
| The login tab | Never handed back. On success the signed-in URL is reopened in a new tab with a plain GET (query dropped if it looks single-use) and the login tab is destroyed, so back-navigation and reload cannot bring back the filled form or re-send its POST. Back/forward cache is off | n/a |
| Revocation | `agent revoke` closes the agent's open relay connection within about 2 s and stops its browser | n/a |

Relay filter (`cdp.py`): browser-level commands are allowlisted; `Tracing`, `Extensions`, `SystemInfo`, `Tethering`, certificate-error overrides, CSP bypass, `DOM.setFileInputFiles`, `Browser.close` and attaching to the browser target are refused; navigation commands accept only `http(s)` and `about:blank`.

## Rules that stop a grant from growing

- Websites are exact origins: scheme, host and port. No wildcards, no subdomain matching.
- A use needs the origin on the account **and** on the grant.
- The check runs in the page, in the same script that fills the field: top-level document on an allowed origin, form `action` (and the submit button's `formaction`) on an allowed origin. That script runs in an isolated JavaScript world, so a page that redefines builtins (`Array.prototype.includes`, `JSON.stringify`, property setters) cannot change its outcome. The broker reads the tab's address from the browser's frame tree, not from page output. A redirect to another origin ends the attempt with `permission_required` before anything is typed, and queues a request for you. Nothing on a page can approve it.
- Import never approves a website and never creates a grant.
- Requests are HMAC-signed over method, path, timestamp, nonce and body; nonces are single-use. The relay and API reject any request carrying an `Origin` header or an unexpected `Host`, which blocks web pages and DNS rebinding.

## Residual risks

1. **The session is the prize.** A signed-in agent can act as you on that site inside the broker's browser. It cannot copy the login out: the relay refuses cookie-reading commands (`Storage.getCookies`, `Network.getCookies`, `Network.getAllCookies`) and strips cookie headers and cookie details from network events and results. Cookies a site leaves readable to page JavaScript (not HttpOnly) are still visible through `document.cookie`, and a site that echoes request headers back in a page would reveal them. On sites that allow it without re-authentication, the agent can change the password or email. Mitigate with narrow grants, sites' own session controls, and action-level approval in the agent harness.
2. **Revocation is not logout.** Revoking a grant or agent does not end website sessions already established. `logout` removes local cookies and storage only.
3. **The relay filter is partly a denylist.** Browser-level commands, including every `Target.*` method, are on an explicit allowlist. Sessions are forced flat, so no command can be tunnelled past the filter, and `Target.sendMessageToTarget` is refused. Page-level DevTools commands not on the denylist are forwarded. A Chromium command that reads local files or persists across the gate, and that we failed to list, would be a hole. Dedicated-user mode limits what such a hole exposes to the broker user's files.
4. **Persistent browser state.** Cookies, local storage and permissions the agent set before a login persist. The broker clears service workers, cache storage and the HTTP cache for the account's sites; other persistent mechanisms may exist.
5. **The website sees the password.** So does any script the site loads. That is inherent in password login.
6. **Heuristic success detection.** Without a `--success-selector`, "the password field is gone" counts as signed in. A page asking for push approval can look the same. Set a success selector for accounts that matter.
7. **Heuristic field detection.** An unusual page could present a non-login field that looks like a username field; the username (not the password) could be typed into it. Password fields are matched by `type=password` only.
8. **Human verification goes through a local page.** The service's browser is headless. The handoff page streams the login tab and replays your input, and the gate stays shut meanwhile (15 minutes in the service). Whoever holds the handoff link drives the login tab, including any "show password" control on the site. Using a link needs a second secret, an 8-character code printed only in your terminal by `gatehouse-admin` (which needs your Mac password). So the link itself leaking, for example through `open`'s process arguments, is not enough. Five wrong codes retire the link, and the attempt is logged. In same-user mode an agent could read both from `state.db`.
9. **Signing keys at rest.** Agent signing keys are stored in `state.db` in clear (the daemon needs them to verify). Anyone who can read that file can impersonate agents, within those agents' grants.
10. **Memory.** Python cannot reliably wipe strings. Decrypted credentials exist in daemon memory during a login and until garbage-collected; the vault key lives for the daemon's lifetime.
11. **Chromium's own password manager** is disabled by preference and flags, not by policy. If it offered to save a password, a headful user could accept.

## Authorization after login

A grant covers signing in. It does not authorize actions inside the account, and the broker does not see or mediate them. Existing agreements in the agent harness still apply: sending email needs approval of exact recipients and content, purchases follow their own authorization, routine pre-authorized actions proceed. Gatehouse neither weakens nor enforces these.
12. **The installer runs as root from your checkout.** Your agents can write to that folder. An agent that changes the code before you rerun `install.sh` would run as root, and then as the broker. The installer shows the commit and any uncommitted changes and asks before proceeding; review changes you did not make.
14. **The app and its password prompts.** The app lives in a folder your account can write to, and so can agents running as you. Before running its bundled installer as root, it copies itself into a root-only folder and verifies the copy's code signature, so edits to the scripts inside the app are refused. Release builds are signed ad hoc, not with a Developer ID, so an agent that rewrote and re-signed the whole app, or that showed a fake password dialog, would not be caught: as with `sudo` in a terminal, only enter your Mac password for an action you just started yourself. Root writes the installer log under `/var/log/gatehouse`, which only root can change. Unlocking gives the app an admin token for up to 15 idle minutes (12 hours at most); it lives in the app's memory, and no admin call returns a password or TOTP secret.
15. **Safari sign-in is weaker, and off by default.** For accounts where you switch on "Also allow in Safari", the service sends the login to the Gatehouse app (running as you) over a channel whose key only an unlocked app receives and keeps in your login keychain. The app types it into Safari through the accessibility interface. Before every character it checks that the field holding the keyboard focus is the one it chose, that the field's own frame is on an approved website, and, for the password, that it is a password field; if not, it stops. When the sign-in doesn't complete, it empties the password field. What it can't prevent: the session then lives in your Safari, where anything that controls Safari can use it; the password is only ever sent to Safari's own process or set directly on the verified password field, never as system-wide key events (if Safari ignores targeted keys, only the username and codes go system-wide, and only while Safari is the frontmost app, checked around every key); and Safari may offer to save the password in Apple Passwords, which an agent clicking through could accept (it still can't read it back without your Touch ID).
13. **Headless fingerprint.** The service's Chrome presents a regular desktop user agent and window size and hides `navigator.webdriver`, which avoids the most common bot checks. Sophisticated bot detection can still tell, and will show a CAPTCHA, which you solve through the handoff.
