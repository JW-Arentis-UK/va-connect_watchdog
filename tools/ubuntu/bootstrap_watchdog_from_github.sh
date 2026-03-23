#!/usr/bin/env bash

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <github_repo_url> [branch] [target_dir]"
  exit 1
fi

REPO_URL="$1"
BRANCH="${2:-main}"
TARGET_DIR="${3:-$HOME/Desktop/va-connect-watchdog}"

if ! command -v git >/dev/null 2>&1; then
  echo "git is not installed. Install it first:"
  echo "  sudo apt update && sudo apt install -y git"
  exit 1
fi

if [[ -d "$TARGET_DIR/.git" ]]; then
  echo "Repository already exists at $TARGET_DIR"
  cd "$TARGET_DIR"
  git fetch origin "$BRANCH"
  git checkout "$BRANCH"
  git pull --ff-only origin "$BRANCH"
else
  git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
fi

cd "$TARGET_DIR/tools/ubuntu"
chmod +x ./*.sh
sudo bash ./update_watchdog.sh
