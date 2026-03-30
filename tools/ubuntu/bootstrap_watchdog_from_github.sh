#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_URL="https://github.com/JW-Arentis-UK/va-connect_watchdog.git"
DEFAULT_BRANCH="master"
DEFAULT_TARGET_DIR="$HOME/Desktop/va-connect-watchdog"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<EOF
Usage: $0 [github_repo_url] [branch] [target_dir]

Example:
  $0
  $0 https://github.com/JW-Arentis-UK/va-connect_watchdog.git
  $0 git@github.com:JW-Arentis-UK/va-connect_watchdog.git master ~/Desktop/va-connect-watchdog
EOF
  exit 1
fi

REPO_URL="${1:-$DEFAULT_REPO_URL}"
BRANCH="${2:-$DEFAULT_BRANCH}"
TARGET_DIR="${3:-$DEFAULT_TARGET_DIR}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
SSH_COMMENT="${SSH_COMMENT:-$(hostname)-gateway-watchdog}"
NEEDS_SSH=0

if [[ "$REPO_URL" == git@* || "$REPO_URL" == ssh://* ]]; then
  NEEDS_SSH=1
fi

install_prereqs() {
  echo "Installing prerequisites..."
  sudo apt update
  if [[ "$NEEDS_SSH" -eq 1 ]]; then
    sudo apt install -y git openssh-client
  else
    sudo apt install -y git
  fi
}

ensure_ssh_key() {
  if [[ "$NEEDS_SSH" -ne 1 ]]; then
    return 0
  fi

  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"

  if [[ ! -f "$SSH_KEY_PATH" ]]; then
    echo "Creating SSH key for this gateway..."
    ssh-keygen -t ed25519 -C "$SSH_COMMENT" -f "$SSH_KEY_PATH" -N ""
  fi

  echo
  echo "Gateway public key:"
  cat "${SSH_KEY_PATH}.pub"
  echo
}

check_github_access() {
  if [[ "$NEEDS_SSH" -ne 1 ]]; then
    return 0
  fi

  if ssh -o BatchMode=yes -T git@github.com >/tmp/watchdog-github-auth.txt 2>&1; then
    return 0
  fi

  if grep -qi "successfully authenticated" /tmp/watchdog-github-auth.txt; then
    return 0
  fi

  echo "GitHub SSH access is not ready yet."
  echo "Add the public key above to the GitHub account or repo access, then rerun this script."
  echo
  cat /tmp/watchdog-github-auth.txt
  exit 1
}

sync_repo() {
  mkdir -p "$(dirname "$TARGET_DIR")"
  if [[ -d "$TARGET_DIR/.git" ]]; then
    echo "Repository already exists at $TARGET_DIR"
    cd "$TARGET_DIR"
    git remote set-url origin "$REPO_URL"
    git fetch origin "$BRANCH"
    git checkout "$BRANCH"
    git pull --ff-only origin "$BRANCH"
  else
    echo "Cloning repository into $TARGET_DIR"
    git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
  fi
}

install_watchdog() {
  cd "$TARGET_DIR/tools/ubuntu"
  chmod +x ./*.sh
  sudo bash ./install_watchdog.sh
}

print_next_steps() {
  cat <<EOF

Gateway bootstrap complete.

Repository:
  $REPO_URL

Useful next commands:
  cd $TARGET_DIR/tools/ubuntu
  bash ./git_update_watchdog.sh
  watchdog-update
  watchdog-restart

Config file:
  /opt/va-connect-watchdog/site-watchdog.json
EOF
}

main() {
  install_prereqs
  ensure_ssh_key
  check_github_access
  sync_repo
  install_watchdog
  print_next_steps
}

main "$@"
