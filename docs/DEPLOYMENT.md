# Deployment (macOS)

Gatehouse runs as a background service under its own hidden macOS user, so the agents, which run as you, cannot read the vault, the broker's memory, or the browser's cookies. You manage it with `gatehouse-admin`, which asks for your Mac password. Agents never have that password, so they cannot grant themselves anything.

## Requirements

- macOS on Apple Silicon or Intel, with an admin account
- [`uv`](https://docs.astral.sh/uv/) (`brew install uv`): used once to fetch a private Python 3.12
- Node.js (`brew install node`): for the agents' browser tool
- Network access to download Chrome for Testing. If that download fails, a signature-checked copy of `/Applications/Google Chrome.app` is used instead

## Install

```sh
cd ~/gatehouse
sudo deploy/macos/install.sh
```

The installer shows the commit it is about to install and asks for confirmation. It runs as root from a folder your agents can write to, so if it reports uncommitted changes you did not make, read `git diff` before continuing.

| What | Where | Owner |
|---|---|---|
| Service user | `_gatehouse`: hidden, no password, no login shell | |
| Code, private Python, private Chrome for Testing | `/opt/gatehouse` | root, read-only to everyone else |
| Vault, state, browser profiles, generated passphrase, log | `/var/db/gatehouse` | `_gatehouse`, mode 700 |
| Broker service, started at boot on `127.0.0.1:8737` | `/Library/LaunchDaemons/com.gatehouse.broker.plist` | root |
| Weekly browser update (Sunday 04:17) | `/Library/LaunchDaemons/com.gatehouse.chrome-update.plist` | root |
| Commands | `/usr/local/bin/gatehouse-admin`, `/usr/local/bin/gatehouse-connect` | root |

The installer finishes with a self-test: the running service unlocks the vault and starts its browser once. Run it again any time with `gatehouse-admin selftest`.

Rerun the installer to upgrade. It keeps the vault, accounts, agents and grants.

## Connect your agents

Run these as yourself, without sudo:

```sh
gatehouse-connect claude-code     # Claude Code (CLI and desktop)
gatehouse-connect codex           # Codex (CLI and app)
gatehouse-connect claude-desktop  # Claude Desktop app chats (quit and reopen the app afterwards)
```

The Claude Desktop app's Code tab uses Claude Code's configuration, so `claude-code` covers it. Its chats read `~/Library/Application Support/Claude/claude_desktop_config.json`; `claude-desktop` adds the two servers there and keeps a `.bak` of the previous file.

Each command does four things:

1. Registers an agent identity with the broker.
2. Stores its keys in `~/.config/gatehouse/agent-<name>.json`, readable only by you.
3. Installs a pinned Playwright MCP browser tool.
4. Adds two MCP servers to that harness at user scope:
   - `gatehouse`: list accounts, request login, check status, log out.
   - `gatehouse-browser`: the browser that holds the signed-in sessions.

Restart any open sessions afterwards.

**T3 Code** runs Claude Code or Codex underneath and uses their configuration, so connecting those two covers it. If a T3 session doesn't show the `gatehouse` tools, that T3 version isn't passing the harness's MCP configuration through. Run `gatehouse-connect t3 none` to print the two server definitions and add them in T3's own settings.

To use some other MCP client, run `gatehouse-connect <name> none` and copy the printed definitions into its settings.

Rerunning `gatehouse-connect` for a name that is already connected reuses its keys. If the key file is lost, it issues new keys for the same agent, and the agent keeps its grants.

## Add accounts and grant them

```sh
gatehouse-admin account add                    # name, username, hidden password, sign-in page, optional TOTP secret
gatehouse-admin account list
gatehouse-admin grant add --agent claude-code --account "Goodreads" --for forever
```

Durations: `once`, `session` (until the broker restarts), `forever` (until revoked), or a date such as `2026-12-31`.

Bulk import from a password-manager CSV export: `gatehouse-admin import ~/Downloads/Passwords.csv`. You pick entries one by one. Imported accounts get no approved website and no grant until you add them, and the command offers to delete the export file afterwards.

### Per-site settings

```sh
gatehouse-admin account edit "Goodreads" --pre-click 'a[href*="sign_in"]'     # click through a "Sign in with email" chooser
gatehouse-admin account edit "Goodreads" --success-selector '#account-menu'   # element present only when signed in
gatehouse-admin account edit "Goodreads" --approve-origin https://www.amazon.com   # a separate sign-in domain
```

Set a success selector for accounts that matter. With it, "signed in" means the selector is present. Without it, "signed in" means the login form went away.

## Day to day

| You want to | Run |
|---|---|
| See or solve a CAPTCHA / code an agent is waiting on | `gatehouse-admin handoff` (opens the live sign-in page in your browser) |
| Answer a request for a website not yet approved | `gatehouse-admin approvals`, then `approve <id> --for ...` or `deny <id>` |
| See what happened | `gatehouse-admin audit` |
| Stop all new logins immediately | `gatehouse-admin logins disable` |
| Take an account away from an agent | `gatehouse-admin grant list --names`, then `grant revoke <id>` |
| Cut an agent off entirely (closes its browser connection within seconds) | `gatehouse-admin agent revoke <name>` |
| Diagnose | `gatehouse-admin status`, `gatehouse-admin selftest`, `gatehouse-admin logs` |

### CAPTCHA and MFA

The broker's browser has no window. When a site asks for a human, the agent gets `human_verification_required` and tells you to run `gatehouse-admin handoff`.

That command opens a page on `127.0.0.1` that shows the sign-in tab live. Your clicks, typing and pastes are sent to it. The page first asks for a code that `gatehouse-admin handoff` prints only in your terminal, so the link alone is useless to an agent. Five wrong codes kill the link (it is logged and a new one is issued). The browser that enters the right code is the only one admitted.

The sign-in waits up to 15 minutes, then fails with `human_verification_timeout`.

For codes you can automate, store the TOTP secret on the account. The broker then types the current code itself.

## Backup and recovery

Everything that matters is in `/var/db/gatehouse/home/vault.json` and `/var/db/gatehouse/passphrase`:

```sh
sudo tar -C /var/db -czf ~/gatehouse-backup.tgz gatehouse/home/vault.json gatehouse/passphrase
```

Keep that archive somewhere safe, because together the two files decrypt your passwords. `state.db` holds agents, grants and history. If you lose it, reconnect your agents and re-grant; no password is lost. Never back up `profiles/`, which holds live website sessions.

## Uninstall

```sh
sudo deploy/macos/uninstall.sh            # remove service and code, keep the vault
sudo deploy/macos/uninstall.sh --purge    # also delete the vault and the _gatehouse user
claude mcp remove gatehouse -s user; claude mcp remove gatehouse-browser -s user
codex mcp remove gatehouse; codex mcp remove gatehouse-browser
```

Website sessions are not ended by uninstalling. Sign out on the websites if that matters.

## Development mode (same user)

For trying things out with test accounts only:

```sh
uv venv --python 3.12 && uv pip install -e '.[dev]'
./run-demo.sh                 # end-to-end demo against a local fake site
.venv/bin/python -m pytest    # test suite (needs Chrome)
```

In this mode, `gatehouse serve` runs as you, so an agent with a shell can read what the broker reads. See `docs/THREAT_MODEL.md`.
