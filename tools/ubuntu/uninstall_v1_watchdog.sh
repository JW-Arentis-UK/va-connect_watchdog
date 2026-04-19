#!/usr/bin/env bash

set -euo pipefail

SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"
LEGACY_INSTALL_DIR="/opt/va-connect-watchdog"
LEGACY_DATA_DIR="/var/lib/va-connect-site-watchdog"
LEGACY_LOG_DIR="/var/log/va-connect-site-watchdog"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

stop_and_remove_unit() {
  local unit_name="$1"
  local unit_path="$SYSTEMD_DIR/$unit_name"

  systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  rm -f "$unit_path"
  echo "Removed $unit_name"
}

remove_legacy_web_unit_if_needed() {
  local unit_name="va-connect-watchdog-web.service"
  local unit_path="$SYSTEMD_DIR/$unit_name"

  if [[ ! -f "$unit_path" ]]; then
    return
  fi

  if grep -Eq 'va_connect_watchdog_web\.py|SITE_WATCHDOG_CONFIG|/opt/va-connect-watchdog/va_connect_watchdog_web\.py' "$unit_path"; then
    stop_and_remove_unit "$unit_name"
  else
    echo "Keeping $unit_name because it does not look like a v1 unit."
  fi
}

remove_legacy_files() {
  local files=(
    "$LEGACY_INSTALL_DIR/va_connect_watchdog.sh"
    "$LEGACY_INSTALL_DIR/va_connect_site_watchdog.py"
    "$LEGACY_INSTALL_DIR/va_connect_watchdog_web.py"
    "$LEGACY_INSTALL_DIR/export_watchdog_incident.sh"
    "$LEGACY_INSTALL_DIR/update_watchdog.sh"
    "$LEGACY_INSTALL_DIR/git_update_watchdog.sh"
    "$LEGACY_INSTALL_DIR/restart_watchdog_services.sh"
    "$LEGACY_INSTALL_DIR/va-connect.env"
    "$LEGACY_INSTALL_DIR/site-watchdog.json"
    "$LEGACY_INSTALL_DIR/repo-dir.txt"
    "$BIN_DIR/watchdog-update"
    "$BIN_DIR/watchdog-restart"
  )

  for path in "${files[@]}"; do
    if [[ -e "$path" ]]; then
      rm -f "$path"
      echo "Removed $path"
    fi
  done
}

remove_legacy_data() {
  if [[ -d "$LEGACY_DATA_DIR" ]]; then
    rm -rf "$LEGACY_DATA_DIR"
    echo "Removed $LEGACY_DATA_DIR"
  fi

  if [[ -d "$LEGACY_LOG_DIR" ]]; then
    rm -rf "$LEGACY_LOG_DIR"
    echo "Removed $LEGACY_LOG_DIR"
  fi
}

main() {
  require_root

  echo "Removing legacy VA-Connect v1 services and files"

  stop_and_remove_unit "va-connect-site-watchdog.service"
  stop_and_remove_unit "va-connect-watchdog.service"
  stop_and_remove_unit "va-connect-watchdog.timer"
  remove_legacy_web_unit_if_needed

  systemctl daemon-reload
  systemctl reset-failed || true

  remove_legacy_files
  remove_legacy_data

  echo "Legacy v1 uninstall complete."
  echo "v2 files were left in place."
}

main "$@"
