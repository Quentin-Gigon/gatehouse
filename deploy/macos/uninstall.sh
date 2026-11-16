#!/bin/bash
# Remove the Gatehouse service. Keeps the vault and state unless you pass --purge.
#
#   sudo deploy/macos/uninstall.sh            stop and remove the service and code; keep /var/db/gatehouse
#   sudo deploy/macos/uninstall.sh --purge    also delete the vault, browser profiles and the _gatehouse user
#
# Website sessions are not ended by this; sign out on the websites if that matters.
# Agent MCP entries are left in Claude Code / Codex: `claude mcp remove gatehouse -s user` etc.
set -euo pipefail
[[ $EUID -eq 0 ]] || exec sudo "$0" "$@"

for l in com.gatehouse.broker com.gatehouse.chrome-update; do
  launchctl bootout "system/$l" 2>/dev/null || true
  rm -f "/Library/LaunchDaemons/$l.plist"
done
rm -f /usr/local/bin/gatehouse-admin /usr/local/bin/gatehouse-connect /var/log/gatehouse-chrome-update.log
rm -rf /opt/gatehouse
echo "Service and code removed."

if [[ "${1:-}" == --purge ]]; then
  read -r -p "Delete the vault and all Gatehouse state for good? Type 'delete': " ans
  [[ "$ans" == delete ]] || { echo "Kept /var/db/gatehouse."; exit 0; }
  rm -rf /var/db/gatehouse
  dscl . -delete /Users/_gatehouse 2>/dev/null || true
  dseditgroup -o delete _gatehouse 2>/dev/null || true
  echo "Vault, state and the _gatehouse user deleted."
else
  echo "Vault and state kept in /var/db/gatehouse (reinstalling picks them up again)."
fi
