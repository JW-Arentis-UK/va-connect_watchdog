#!/usr/bin/env bash
set -Eeuo pipefail

# Use this from a gateway terminal when the web update button cannot start.
INSTALL_DIR="${VA_WATCHDOG_INSTALL_DIR:-/opt/va-connect-watchdog-v3}"
REPO_DIR="$INSTALL_DIR"
APP_DIR="$REPO_DIR/v3"
REMOTE="${1:-origin}"
BRANCH="${2:-codex/gui-refresh}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=VA_WATCHDOG_INSTALL_DIR "$0" "$REMOTE" "$BRANCH"
fi

fail() {
  printf '[VA-Watchdog recovery] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -d "$REPO_DIR/.git" ]] || fail "Git checkout was not found at $REPO_DIR"
[[ -f "$APP_DIR/scripts/update.sh" ]] || fail "Watchdog update script was not found at $APP_DIR/scripts/update.sh"

git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" fetch "$REMOTE" "$BRANCH"
git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR" pull --ff-only "$REMOTE" "$BRANCH"

# Run the freshly pulled updater so dependencies and the service definition are applied.
exec /bin/bash "$APP_DIR/scripts/update.sh" "$REMOTE" "$BRANCH"
