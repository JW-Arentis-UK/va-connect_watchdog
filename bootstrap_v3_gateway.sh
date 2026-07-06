#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-https://github.com/JW-Arentis-UK/va-connect_watchdog.git}"
INSTALL_DIR="${2:-/opt/va-connect-watchdog-v3}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is required but not installed." >&2
  exit 1
fi

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing checkout in $INSTALL_DIR"
  sudo git -C "$INSTALL_DIR" pull --ff-only
else
  echo "Cloning $REPO_URL into $INSTALL_DIR"
  sudo git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

echo "Installing v3 watchdog"
sudo ./v3/scripts/install.sh
