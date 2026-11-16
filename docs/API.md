# Agent interface

## MCP tools (`gatehouse-mcp`)

| Tool | Arguments | Returns |
|---|---|---|
| `list_authorized_accounts` | none | `{status, accounts:[{account_id, name, username, origins, has_totp}]}` |
| `request_login` | `account_id`, optional `browser_session_id`, optional `wait_seconds` (default 60) | `{request_id, account_id, status, detail}` |
| `get_login_status` | `request_id` | same shape |
| `logout` | `account_id`, optional `browser_session_id` | `{account_id, status, detail}` |

There is no tool, endpoint or parameter that returns a password or TOTP value.

The adapter reads `GATEHOUSE_AGENT_CONFIG`, a JSON file `{"url", "agent_id", "sign_key"}` written by `gatehouse agent add`.

### Statuses

| Status | Meaning | What the agent should do |
|---|---|---|
| `signed_in` | Login completed | Reconnect the browser tool and continue |
| `already_signed_in` | A session was already there | Continue |
| `in_progress` | Still working | Poll `get_login_status` |
| `human_verification_required` | A person must finish a challenge in the browser window | Tell the user; poll |
| `permission_required` | Grant expired, used up, or the site redirected to a website not approved | Tell the user; they run `gatehouse approvals` |
| `permission_denied` | No grant, revoked, logins disabled, or unknown account | Stop |
| `vault_locked` | Broker running without the vault key | Tell the user |
| `login_failed` | Rejected credentials, timeout, navigation or page error | Stop. Do not retry |
| `unsupported_login_flow` | No recognizable form | Stop |
| `cancelled` | Cancelled by the agent | n/a |

`detail` is a fixed word such as `credentials_rejected`, `redirected_to_unapproved_origin`, `form_action_mismatch`, `human_verification_timeout`, `blocked_after_repeated_failures_user_must_reset`. It never contains page content or values.

## HTTP API

`POST` to `http://127.0.0.1:<port>` with a JSON body.

| Path | Body |
|---|---|
| `/v1/accounts` | `{}` |
| `/v1/browser` | `{}` → `{browser_session_id, gate_open}`; starts the agent's browser if needed |
| `/v1/login` | `{account_id, browser_session_id}` |
| `/v1/login/status` | `{request_id}` |
| `/v1/login/cancel` | `{request_id}` |
| `/v1/logout` | `{account_id, browser_session_id}` |

Headers on every request:

```
X-GH-Agent:     agt_...
X-GH-Timestamp: <unix seconds>            (within 60 s of the broker's clock)
X-GH-Nonce:     <16-128 random characters, never reused>
X-GH-Signature: hex(HMAC-SHA256(sign_key, METHOD "\n" PATH "\n" TIMESTAMP "\n" NONCE "\n" hex(SHA256(body))))
```

`gatehouse/client.py` is a reference implementation in about 40 lines.

Behaviour: one login runs at a time per browser. A second `/v1/login` for the same account while one is running returns the running request. A request can be read or cancelled only by the agent that made it. `browser_session_id` changes whenever the agent's browser restarts, and a login naming another agent's session is refused.

## Browser relay

`gatehouse agent add` prints `http://127.0.0.1:<port>/cdp/<token>`. Give it to a DevTools-capable browser tool:

- `GET /cdp/<token>/json/version` returns `webSocketDebuggerUrl`, as Chromium's own endpoint would.
- `ws://127.0.0.1:<port>/cdp/<token>/devtools/browser` carries the protocol.

Tested with Playwright's `connect_over_cdp`. During a protected login the socket closes and reconnects get HTTP 423; reconnect after `signed_in`. After a login all previous tabs are gone and one tab holds the signed-in page.

The token is a capability for that agent's browser. Treat it like a key; the broker's access log is disabled so it is not written to disk.
