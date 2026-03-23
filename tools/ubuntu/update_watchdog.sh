#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

main() {
  require_root
  cd "$PROJECT_ROOT"
  bash "$SCRIPT_DIR/install_watchdog.sh"
  bash "$SCRIPT_DIR/restart_watchdog_services.sh"

  echo
  echo "Verification:"
  grep -n "PC Stats - Last 24 Hours" /opt/va-connect-watchdog/va_connect_watchdog_web.py || true
  grep -n "metrics.jsonl" /opt/va-connect-watchdog/va_connect_watchdog_web.py || true
  systemctl status va-connect-site-watchdog.service --no-pager || true
  systemctl status va-connect-watchdog-web.service --no-pager || true
  ls -l /var/log/va-connect-site-watchdog/metrics.jsonl || true

  cat <<EOF

Update complete.
Open the page and hard refresh it:
  Ctrl+Shift+R

Default URL:
  http://localhost/
EOF
}

main "$@"
