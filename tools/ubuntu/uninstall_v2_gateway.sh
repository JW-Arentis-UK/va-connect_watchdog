#!/usr/bin/env bash

set -euo pipefail

TARGET_DIR="/opt/va-connect-watchdog"
SYSTEMD_DIR="/etc/systemd/system"
DATA_DIRS=(
  "/var/lib/va-connect-v2"
  "/var/lib/va-connect-site-watchdog"
)
LOG_DIRS=(
  "/var/log/va-connect-site-watchdog"
)
UNITS=(
  "va-connect-watchdog-web.service"
  "site_watchdog.service"
  "va-connect-site-watchdog.service"
  "va-connect-watchdog.service"
  "va-connect-watchdog.timer"
)
BIN_FILES=(
  "/usr/local/bin/watchdog-update"
  "/usr/local/bin/watchdog-restart"
)

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

confirm() {
  if [[ "${1:-}" == "--yes" ]]; then
    return 0
  fi

  cat <<EOF
This will remove the v2 gateway install:
  - $TARGET_DIR
  - ${DATA_DIRS[*]}
  - ${LOG_DIRS[*]}
  - the v2 and legacy VA-Connect systemd units
  - the legacy watchdog wrapper scripts in /usr/local/bin

It will not remove system packages or user-local Python packages.

Type DELETE to continue.
EOF
  read -r answer
  if [[ "$answer" != "DELETE" ]]; then
    echo "Aborted."
    exit 1
  fi
}

stop_and_remove_unit() {
  local unit_name="$1"
  systemctl disable --now "$unit_name" >/dev/null 2>&1 || true
  rm -f "$SYSTEMD_DIR/$unit_name"
}

remove_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    rm -rf "$path"
    echo "Removed $path"
  fi
}

remove_backup_dirs() {
  shopt -s nullglob
  for backup_dir in /opt/va-connect-watchdog.backup.*; do
    rm -rf "$backup_dir"
    echo "Removed $backup_dir"
  done
  shopt -u nullglob
}

main() {
  require_root
  confirm "${1:-}"

  echo "Stopping and removing VA-Connect services..."
  for unit in "${UNITS[@]}"; do
    stop_and_remove_unit "$unit"
  done

  echo "Removing files and directories..."
  for path in "${BIN_FILES[@]}"; do
    remove_path "$path"
  done
  for path in "${DATA_DIRS[@]}"; do
    remove_path "$path"
  done
  for path in "${LOG_DIRS[@]}"; do
    remove_path "$path"
  done
  remove_path "$TARGET_DIR"
  remove_backup_dirs

  systemctl daemon-reload
  systemctl reset-failed >/dev/null 2>&1 || true

  echo "v2 uninstall complete."
}

main "$@"
