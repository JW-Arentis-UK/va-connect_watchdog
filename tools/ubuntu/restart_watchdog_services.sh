#!/usr/bin/env bash

set -euo pipefail

SITE_SERVICE_NAME="va-connect-site-watchdog.service"
WEB_SERVICE_NAME="va-connect-watchdog-web.service"
TIMER_NAME="va-connect-watchdog.timer"
PROCESS_SERVICE_NAME="va-connect-watchdog.service"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

show_status() {
  systemctl --no-pager --full status "$SITE_SERVICE_NAME" || true
  systemctl --no-pager --full status "$WEB_SERVICE_NAME" || true
  systemctl --no-pager --full status "$TIMER_NAME" || true
  systemctl --no-pager --full status "$PROCESS_SERVICE_NAME" || true
}

main() {
  require_root
  systemctl daemon-reload
  systemctl disable --now "$TIMER_NAME" || true
  systemctl stop "$PROCESS_SERVICE_NAME" || true
  systemctl restart "$SITE_SERVICE_NAME"
  systemctl restart "$WEB_SERVICE_NAME"
  echo "Watchdog services restarted."
  show_status
}

main "$@"
