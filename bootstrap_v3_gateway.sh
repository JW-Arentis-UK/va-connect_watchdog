#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${1:-https://github.com/JW-Arentis-UK/va-connect_watchdog.git}"
REPO_REF="${2:-codex/gui-refresh}"
INSTALL_DIR="${3:-/opt/va-connect-watchdog-v3}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is missing; installing it first..."
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is required to install git automatically." >&2
    exit 1
  fi
  sudo apt-get update
  sudo apt-get install -y git
fi

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing checkout in $INSTALL_DIR"
  sudo git -C "$INSTALL_DIR" fetch origin "$REPO_REF"
  sudo git -C "$INSTALL_DIR" checkout -B "$REPO_REF" "origin/$REPO_REF"
  sudo git -C "$INSTALL_DIR" pull --ff-only origin "$REPO_REF"
else
  echo "Cloning $REPO_URL ($REPO_REF) into $INSTALL_DIR"
  sudo git clone --branch "$REPO_REF" --single-branch "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

echo "Installing v3 watchdog"
sudo ./v3/scripts/install.sh
