# Deployment

> The macOS steps below are a design, **not yet executed on a Mac**. Treat every command as needing verification, and report what breaks.

## Requirements

- macOS on Apple Silicon (target) or Linux (tested)
- Python 3.11+
- Chromium, Chrome for Testing, or Chrome. Set `GATEHOUSE_CHROME` if it is not in a standard location

## Supported mode: dedicated broker user (macOS)

Goal: the agent's user cannot read the vault, the daemon's memory, or the browser profile.

1. Create a standard user, e.g. `gatehouse`, in System Settings → Users & Groups.
2. Log in as that user in its own graphical session. Human verification needs a visible browser window, so the broker must run inside a GUI session: use Screen Sharing to the M1 and sign in as `gatehouse`, or fast user switching. A LaunchDaemon without a window server cannot show the browser.
3. In that session:
   ```sh
   python3 -m pip install --user gatehouse-broker     # or: pip install -e . from a checkout
   gatehouse init
   gatehouse serve
   ```
4. Still as `gatehouse`: `gatehouse account add`, then
   ```sh
   gatehouse agent add codex --write-config /Users/Shared/gatehouse/agent-codex.json
   ```
   Move that file to the agent user's home, owner-only (`chmod 600`), and pass the printed browser endpoint to the agent user's configuration.
5. Check from the agent's user that `ls /Users/gatehouse/.gatehouse` is denied.

Management commands (`approvals`, `grant`, `audit`) run as `gatehouse`, e.g. over `ssh gatehouse@localhost` or in its Screen Sharing session.

Unattended restart: `gatehouse --passphrase-file /Users/gatehouse/.gatehouse-pass serve` with the file `chmod 600`. This trades the "vault locked after reboot" property for availability; the file is as sensitive as the vault.

## Evaluation mode: same user

`gatehouse init && gatehouse serve` as yourself. Fine for trying the workflow with synthetic or low-value accounts. An agent with a shell under the same user can defeat it; see `docs/THREAT_MODEL.md`.

## Wiring Codex (and T3 Code)

Codex reads MCP servers from `~/.codex/config.toml`:

```toml
[mcp_servers.gatehouse]
command = "gatehouse-mcp"
env = { GATEHOUSE_AGENT_CONFIG = "/Users/you/.config/gatehouse/agent-codex.json" }

[mcp_servers.browser]
command = "npx"
args = ["@playwright/mcp@latest", "--cdp-endpoint", "http://127.0.0.1:8737/cdp/<token from agent add>"]
```

The agent must browse with the `browser` server above, because only that browser holds the brokered sessions. A harness's built-in browser tool is a different browser and will not be signed in.

Unverified, check on the M1:

- That T3 Code 0.1.9 (or the version in use) passes Codex's MCP configuration through unchanged.
- That the Playwright MCP server reconnects cleanly after the relay closes during a login. If it does not, restart that MCP server after `signed_in`.
- That T3's built-in browser tool can be disabled or is simply not used for brokered sites.

T3's secret-request files are not used anywhere in this design.

## Per-site settings

```sh
gatehouse account edit <id> --pre-click 'a[href*="sign_in"]'      # click through a "Sign in with email" chooser
gatehouse account edit <id> --success-selector '#account-menu'    # element that exists only when signed in
gatehouse account edit <id> --approve-origin https://auth.example.com
```

A success selector makes "signed in" a positive check instead of "the form went away", and makes "already signed in" reliable.

## Backup and recovery

- Back up `~/.gatehouse/vault.json`. It is encrypted; store the passphrase separately.
- There is no passphrase recovery.
- `state.db` holds agents, grants and history. If lost, re-register agents and re-grant; no credential is lost.
- Never back up or commit `profiles/` (browser sessions) or agent config files.

## Upgrade

Stop the daemon, `pip install -U gatehouse-broker` (or `git pull` in a checkout), start it. The vault file carries a version number; 0.1.0 writes version 1. Read release notes before upgrading across a minor version while pre-1.0.

## Uninstall

Stop the daemon, delete `~/.gatehouse`, remove the dedicated user, and sign out of the websites' sessions from the websites themselves.
