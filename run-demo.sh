#!/usr/bin/env bash
# End-to-end Gatehouse demo against a local fake login site. Nothing real is touched:
# the vault, broker state and Chrome profile live in a temporary directory that is
# deleted on exit, and every credential is synthetic (see tests/fakesite.py).
#
#   ./run-demo.sh              Chrome window visible, so you can watch the broker type
#   ./run-demo.sh --headless   no window
#   ./run-demo.sh --keep       keep the temporary directory for inspection
set -euo pipefail

HEADLESS=()
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --headless) HEADLESS=(--headless) ;;
    --keep) KEEP=1 ;;
    -h|--help) sed -n 2,8p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

bold() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '   %s\n' "$*"; }
run()  { printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }

# --- Python environment ---------------------------------------------------------
bold "Preparing Python environment (.venv)"
if [[ ! -x .venv/bin/python ]]; then
  if command -v uv >/dev/null; then
    uv venv --quiet --python 3.12 .venv
  else
    PY="$(command -v python3.13 || command -v python3.12 || command -v python3.11 || true)"
    [[ -n "$PY" ]] || { echo "error: needs Python 3.11+ or uv" >&2; exit 1; }
    "$PY" -m venv .venv
  fi
fi
if command -v uv >/dev/null; then
  uv pip install --quiet --python .venv/bin/python -e .
else
  .venv/bin/python -m pip install --quiet -e .
fi
PY="$ROOT/.venv/bin/python"
export PATH="$ROOT/.venv/bin:$PATH"
GH=gatehouse
note "$("$PY" --version), gatehouse installed in editable mode"

# --- Throwaway state ------------------------------------------------------------
DEMO="$(mktemp -d "${TMPDIR:-/tmp}/gatehouse-demo.XXXXXX")"
export GATEHOUSE_HOME="$DEMO/home"
PASSFILE="$DEMO/passphrase"
( umask 077; printf 'demo passphrase, not secret\n' > "$PASSFILE" )
export GATEHOUSE_PASSPHRASE_FILE="$PASSFILE"
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [[ $KEEP == 1 ]]; then echo; echo "Demo state kept in $DEMO"; else rm -rf "$DEMO"; fi
}
trap cleanup EXIT

read -r SITE_PORT OTHER_PORT BROKER_PORT < <("$PY" -c '
import socket
socks = [socket.socket() for _ in range(3)]
for s in socks: s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))')
SITE="http://127.0.0.1:$SITE_PORT"

wait_for() {  # wait_for URL NAME LOGFILE
  for _ in $(seq 1 100); do
    curl -s -o /dev/null "$1" && return 0
    sleep 0.1
  done
  echo "error: $2 did not start; log:" >&2; cat "$3" >&2; exit 1
}

# --- Fake website ---------------------------------------------------------------
bold "Starting the fake website at $SITE"
"$PY" -c '
import sys
sys.path.insert(0, "tests")
from aiohttp import web
from fakesite import Site
site = Site()
site.other_origin = "http://127.0.0.1:" + sys.argv[2]
web.run_app(site.app(), host="127.0.0.1", port=int(sys.argv[1]), print=None)
' "$SITE_PORT" "$OTHER_PORT" > "$DEMO/site.log" 2>&1 &
PIDS+=($!)
wait_for "$SITE/login" "fake website" "$DEMO/site.log"
note "Synthetic account: reader@example.test (password lives only in tests/fakesite.py)"

# --- Owner setup ------------------------------------------------------------------
bold "1. Owner creates the vault"
# Explicit flag: init only skips its "Repeat:" prompt for --passphrase-file, not the env var.
run "$GH" --passphrase-file "$PASSFILE" init

# `account add` is interactive (hidden password prompt). Feed it scripted answers and
# show the prompts as a person would see them, with the password masked.
add_account() {  # add_account NAME PASSWORD
  printf '%s\n' "$1" "reader@example.test" "$2" "$SITE/login" "n" "" |
    "$PY" -c '
import builtins, getpass, sys
from gatehouse.cli import main
def answer(prompt, hidden=False):
    value = sys.stdin.readline().rstrip("\n")
    print(prompt + ("*" * len(value) if hidden else value))
    return value
builtins.input = answer
getpass.getpass = lambda prompt="": answer(prompt, hidden=True)
main(["account", "add"])'
}

bold "2. Owner adds two accounts (only one will be granted)"
printf '\033[2m$ %s account add\033[0m\n' "$GH"
add_account "Demo Books" "synthetic-Passw0rd!-not-real"
echo
printf '\033[2m$ %s account add\033[0m\n' "$GH"
add_account "Demo Bank" "another-synthetic-password"
echo
run "$GH" account list
BOOKS_ID="$("$GH" account list | awk '/Demo Books/ {print $1}')"
BANK_ID="$("$GH" account list | awk '/Demo Bank/ {print $1}')"

bold "3. Owner starts the broker on port $BROKER_PORT"
PYTHONUNBUFFERED=1 "$GH" serve --port "$BROKER_PORT" --human-timeout 30 ${HEADLESS[@]+"${HEADLESS[@]}"} > "$DEMO/broker.log" 2>&1 &
PIDS+=($!)
wait_for "http://127.0.0.1:$BROKER_PORT/" "broker" "$DEMO/broker.log"
note "$(head -1 "$DEMO/broker.log")"

bold "4. Owner registers an agent and grants it one account"
AGENT_OUT="$(run "$GH" agent add demo-agent --write-config "$DEMO/agent-demo.json")"
printf '%s\n' "$AGENT_OUT"
CDP_URL="$(printf '%s\n' "$AGENT_OUT" | awk '/\/cdp\// {print $1}')"
run "$GH" grant add --agent demo-agent --account "Demo Books" --for forever

# --- Agent side ---------------------------------------------------------------------
bold "5. The agent uses the broker (it only holds its own API key, never a password)"
"$PY" - "$DEMO/agent-demo.json" "$CDP_URL" "$BOOKS_ID" "$BANK_ID" <<'PY'
import asyncio, json, sys, time
import aiohttp
from gatehouse.client import BrokerClient

cfg_path, cdp_url, books, bank = sys.argv[1:]
cfg = json.load(open(cfg_path))
agent = BrokerClient(cfg["url"], cfg["agent_id"], cfg["sign_key"])
seen = []

def call(path, payload=None):
    _, r = agent.call(path, payload)
    seen.append(json.dumps(r))
    return r

def login(account_id):
    sid = call("/v1/browser")["browser_session_id"]
    r = call("/v1/login", {"account_id": account_id, "browser_session_id": sid})
    end = time.time() + 60
    while r.get("request_id") and r["status"] in ("in_progress", "human_verification_required") and time.time() < end:
        time.sleep(0.5)
        r = call("/v1/login/status", {"request_id": r["request_id"]})
    return r

print("   accounts the agent can see:")
for a in call("/v1/accounts")["accounts"]:
    print(f"     - {a.get('name')} <{a.get('username')}>")

r = login(bank)
print(f"   login to Demo Bank (no grant)   -> {r['status']} ({r['detail']})")
r = login(books)
print(f"   login to Demo Books (granted)   -> {r['status']}")
r = login(books)
print(f"   login to Demo Books again       -> {r['status']} (session reused, no password sent)")

async def peek():
    # What the agent's browser tool does after the broker hands the browser back.
    ws_url = cdp_url.replace("http://", "ws://") + "/devtools/browser"
    async with aiohttp.ClientSession() as http, http.ws_connect(ws_url, max_msg_size=0) as ws:
        n = 0
        async def cdp(method, params=None, session=None):
            nonlocal n
            n += 1
            msg = {"id": n, "method": method, "params": params or {}}
            if session:
                msg["sessionId"] = session
            await ws.send_str(json.dumps(msg))
            while True:
                reply = json.loads((await ws.receive(timeout=20)).data)
                seen.append(json.dumps(reply))
                if reply.get("id") == n:
                    return reply["result"]
        pages = [t for t in (await cdp("Target.getTargets"))["targetInfos"] if t["type"] == "page"]
        sess = (await cdp("Target.attachToTarget", {"targetId": pages[0]["targetId"], "flatten": True}))["sessionId"]
        ev = await cdp("Runtime.evaluate", {"expression": "location.pathname + ' | ' + document.body.innerText",
                                            "returnByValue": True}, sess)
        return ev["result"]["value"].splitlines()[0]

print(f"   agent reconnects to the browser and reads the page: {asyncio.run(peek())!r}")
leaked = any("synthetic-Passw0rd" in s for s in seen)
print(f"   password appeared in anything the agent received: {'YES (bug!)' if leaked else 'no'}")
sys.exit(1 if leaked else 0)
PY

# --- Owner review -------------------------------------------------------------------
bold "6. Owner reviews what happened"
run "$GH" grant list --names
run "$GH" audit

bold "Done"
note "Every login above went through a Chrome only the broker controls."
[[ $KEEP == 1 ]] || note "Temporary vault, profile and keys are being deleted."
