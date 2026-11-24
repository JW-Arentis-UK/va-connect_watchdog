#!/usr/bin/env bash
set -Eeuo pipefail
# Bootstrap older installations without executing their installed updater.
INSTALL_DIR="${VA_WATCHDOG_INSTALL_DIR:-/opt/va-connect-watchdog-v3}"
REMOTE="${1:-origin}"
BRANCH="${2:-codex/gui-refresh}"
if [[ "$EUID" -ne 0 ]]; then
  exec sudo --preserve-env=VA_WATCHDOG_INSTALL_DIR bash "$0" "$@"
fi
[[ -d "$INSTALL_DIR/.git" ]] || { echo "No V3 checkout at $INSTALL_DIR" >&2; exit 1; }
work_dir=$(mktemp -d)
trap 'rm -rf -- "$work_dir"' EXIT
# Download the current orchestrator before allowing Git to change installed files.
wget -O "$work_dir/update.sh" \
  https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/v3/scripts/update.sh
VA_WATCHDOG_INSTALL_DIR="$INSTALL_DIR" bash "$work_dir/update.sh" "$REMOTE" "$BRANCH"
