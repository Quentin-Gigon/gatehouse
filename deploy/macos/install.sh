#!/bin/bash
# Install or upgrade Gatehouse as a background service on macOS.
#
#   sudo deploy/macos/install.sh
#
# What it sets up (rerun any time to upgrade; it keeps your vault, accounts and grants):
#   _gatehouse                    hidden system user that owns the vault and runs the broker
#   /opt/gatehouse                code, private Python, private Chrome for Testing (root-owned)
#   /var/db/gatehouse             vault, state, browser profiles, passphrase (only _gatehouse can read)
#   /Library/LaunchDaemons/...    broker at boot on 127.0.0.1:8737, weekly Chrome update
#   /usr/local/bin/gatehouse-admin    management CLI (asks for your Mac password via sudo)
#   /usr/local/bin/gatehouse-connect  registers an agent and wires it into Claude Code / Codex
set -euo pipefail

SVC=_gatehouse
PREFIX=/opt/gatehouse
STATE=/var/db/gatehouse
PORT=8737
LABEL=com.gatehouse.broker
UPDATE_LABEL=com.gatehouse.chrome-update
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"
[[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]] || { echo "Run this with sudo from your own account." >&2; exit 1; }
INVOKER_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory | awk '{print $2}')"

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

# This script runs as root from a folder your agents can write to. Know what you are installing.
if [[ "${1:-}" != --yes ]]; then
  rev="$(sudo -u "$SUDO_USER" git -C "$REPO" log -1 --format='%h %s' 2>/dev/null || echo 'not a git checkout')"
  dirty="$(sudo -u "$SUDO_USER" git -C "$REPO" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  echo "Installing Gatehouse as root from $REPO"
  echo "  commit: $rev"
  [[ "$dirty" == 0 ]] || echo "  WARNING: $dirty uncommitted change(s) in the checkout; review them (git -C $REPO diff) first"
  read -r -p "Continue? [y/N] " ans
  [[ "$ans" =~ ^[Yy] ]] || exit 1
fi
# From /, since the service user cannot enter the directory this script was started from.
as_svc() ( cd / && sudo -u "$SVC" /usr/bin/env -i HOME="$STATE" GATEHOUSE_HOME="$STATE/home" \
             GATEHOUSE_CHROME="$PREFIX/chrome/current" PATH=/usr/bin:/bin "$@" )

# --- service account -------------------------------------------------------------
step "Service account $SVC"
if dscl . -read "/Users/$SVC" >/dev/null 2>&1; then
  echo "exists"
else
  ID=""
  for i in $(seq 450 499); do
    if ! dscl . -search /Users UniqueID "$i" | grep -q . && ! dscl . -search /Groups PrimaryGroupID "$i" | grep -q .; then
      ID=$i; break
    fi
  done
  [[ -n "$ID" ]] || { echo "no free system id between 450 and 499" >&2; exit 1; }
  dseditgroup -o create -i "$ID" -r "Gatehouse broker" "$SVC"
  dscl . -create "/Users/$SVC"
  dscl . -create "/Users/$SVC" UniqueID "$ID"
  dscl . -create "/Users/$SVC" PrimaryGroupID "$ID"
  dscl . -create "/Users/$SVC" UserShell /usr/bin/false
  dscl . -create "/Users/$SVC" NFSHomeDirectory "$STATE"
  dscl . -create "/Users/$SVC" RealName "Gatehouse broker"
  dscl . -create "/Users/$SVC" Password '*'
  dscl . -create "/Users/$SVC" IsHidden 1
  echo "created with id $ID (hidden, no login, no password)"
fi

install -d -o "$SVC" -g "$SVC" -m 700 "$STATE" "$STATE/home"
install -d -o root -g wheel -m 755 "$PREFIX" "$PREFIX/bin" "$PREFIX/chrome"

# --- Python and the gatehouse package -------------------------------------------
step "Private Python and Gatehouse $(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/pyproject.toml")"
UV_SRC="$(sudo -u "$SUDO_USER" -i command -v uv 2>/dev/null || true)"
[[ -x "$UV_SRC" ]] || UV_SRC="$INVOKER_HOME/.local/bin/uv"
[[ -x "$UV_SRC" ]] || { echo "uv is required: https://docs.astral.sh/uv/ (brew install uv)" >&2; exit 1; }
install -o root -g wheel -m 755 "$UV_SRC" "$PREFIX/bin/uv"
export UV_PYTHON_INSTALL_DIR="$PREFIX/python" UV_CACHE_DIR="$PREFIX/.uv-cache" UV_NO_CONFIG=1
"$PREFIX/bin/uv" python install --quiet --no-bin 3.12
PY="$("$PREFIX/bin/uv" python find --managed-python 3.12)"

BUILD="$(mktemp -d)"
trap 'rm -rf "$BUILD"' EXIT
cp -R "$REPO/src" "$REPO/pyproject.toml" "$REPO/README.md" "$REPO/LICENSE" "$BUILD/"
rm -rf "$BUILD"/src/*.egg-info
find "$BUILD" -name __pycache__ -type d -prune -exec rm -rf {} +
# Build the new environment in place; on failure put the previous one back.
rm -rf "$PREFIX/venv.old"
if [[ -d "$PREFIX/venv" ]]; then mv "$PREFIX/venv" "$PREFIX/venv.old"; fi
if ! { "$PY" -m venv "$PREFIX/venv" &&
       "$PREFIX/bin/uv" pip install --quiet --python "$PREFIX/venv/bin/python" --require-hashes -r "$REPO/deploy/requirements.lock" &&
       "$PREFIX/bin/uv" pip install --quiet --python "$PREFIX/venv/bin/python" --no-deps --no-build-isolation "$BUILD"; }; then
  rm -rf "$PREFIX/venv"
  if [[ -d "$PREFIX/venv.old" ]]; then mv "$PREFIX/venv.old" "$PREFIX/venv"; fi
  echo "installing the Python package failed; previous version kept" >&2
  exit 1
fi
rm -rf "$PREFIX/venv.old"
chown -R root:wheel "$PREFIX"
"$PREFIX/venv/bin/gatehouse" --help >/dev/null && echo "gatehouse installed in $PREFIX/venv"

# --- helper scripts ----------------------------------------------------------------
step "Commands"
render() { sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@STATE@|$STATE|g" -e "s|@SVC@|$SVC|g" -e "s|@PORT@|$PORT|g" \
               -e "s|@LABEL@|$LABEL|g" -e "s|@UPDATE_LABEL@|$UPDATE_LABEL|g" "$1"; }
for f in update-chrome; do render "$REPO/deploy/macos/$f" > "$PREFIX/bin/$f"; chmod 755 "$PREFIX/bin/$f"; done
install -d -o root -g wheel -m 755 /usr/local/bin
for f in gatehouse-admin gatehouse-connect; do
  render "$REPO/deploy/macos/$f" > "/usr/local/bin/$f"; chown root:wheel "/usr/local/bin/$f"; chmod 755 "/usr/local/bin/$f"
done
echo "/usr/local/bin/gatehouse-admin, /usr/local/bin/gatehouse-connect"

# --- browser -----------------------------------------------------------------------------
step "Browser"
"$PREFIX/bin/update-chrome"

# --- vault -----------------------------------------------------------------------------------
step "Vault"
if [[ ! -s "$STATE/passphrase" ]]; then
  ( umask 077; /usr/bin/openssl rand -base64 33 > "$STATE/passphrase" )
  chown "$SVC:$SVC" "$STATE/passphrase"; chmod 600 "$STATE/passphrase"
fi
if [[ -e "$STATE/home/vault.json" ]]; then
  echo "existing vault kept"
else
  as_svc "$PREFIX/venv/bin/gatehouse" --passphrase-file "$STATE/passphrase" init
fi

# --- launchd ------------------------------------------------------------------------------------
step "Background service"
for l in "$LABEL" "$UPDATE_LABEL"; do
  render "$REPO/deploy/macos/$l.plist" > "/Library/LaunchDaemons/$l.plist"
  chown root:wheel "/Library/LaunchDaemons/$l.plist"; chmod 644 "/Library/LaunchDaemons/$l.plist"
  launchctl bootout "system/$l" 2>/dev/null || true
  # bootout returns before the old job is fully gone; bootstrap can fail briefly with "5: Input/output error"
  for attempt in 1 2 3 4 5 6 7 8 9 10; do
    launchctl bootstrap system "/Library/LaunchDaemons/$l.plist" 2>/dev/null && break
    [[ $attempt -lt 10 ]] || launchctl bootstrap system "/Library/LaunchDaemons/$l.plist"
    sleep 1
  done
  launchctl enable "system/$l"
done
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 0.5
done
if curl -s -o /dev/null "http://127.0.0.1:$PORT/"; then
  echo "broker running on 127.0.0.1:$PORT"
  step "Self-test (starts the broker's browser once as $SVC)"
  if ! as_svc "$PREFIX/venv/bin/gatehouse" --passphrase-file "$STATE/passphrase" selftest; then
    echo "self-test failed; broker log:" >&2
    tail -30 "$STATE/broker.log" >&2 || true
    exit 1
  fi
else
  echo "broker did not come up; last log lines:" >&2
  tail -20 "$STATE/broker.log" >&2 || true
  exit 1
fi

cat <<EOF

Gatehouse is installed and running.

Next:
  gatehouse-admin account add            add a website login (prompts; password stays hidden)
  gatehouse-connect claude-code          give Claude Code its own agent identity and tools
  gatehouse-connect codex                same for Codex (T3 Code uses these configs too)
  gatehouse-admin grant add --agent claude-code --account "<name>" --for forever

The vault passphrase was generated for you and lives in $STATE/passphrase,
readable only by $SVC. Back up with: sudo tar -C /var/db -czf gatehouse-backup.tgz gatehouse/home/vault.json gatehouse/passphrase
EOF
