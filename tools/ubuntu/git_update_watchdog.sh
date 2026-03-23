#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_DIR="$HOME/Desktop/va-connect-watchdog"
REPO_DIR="${1:-${REPO_DIR:-$DEFAULT_REPO_DIR}}"
BRANCH="${BRANCH:-}"

run_as_repo_user() {
  local repo_owner
  repo_owner="$(stat -c '%U' "$REPO_DIR")"
  if [[ "$(id -un)" == "$repo_owner" ]]; then
    "$@"
  else
    sudo -u "$repo_owner" "$@"
  fi
}

main() {
  if [[ ! -d "$REPO_DIR/.git" ]]; then
    echo "Git repository not found at $REPO_DIR"
    echo "Clone it first with bootstrap_watchdog_from_github.sh"
    exit 1
  fi

  cd "$REPO_DIR"

  if [[ -n "$BRANCH" ]]; then
    run_as_repo_user git fetch origin "$BRANCH"
    run_as_repo_user git checkout "$BRANCH"
    run_as_repo_user git pull --ff-only origin "$BRANCH"
  else
    run_as_repo_user git pull --ff-only
  fi

  sudo WATCHDOG_SKIP_GIT_PULL=1 bash "$REPO_DIR/tools/ubuntu/update_watchdog.sh"
}

main "$@"
