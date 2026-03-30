#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SKIP_GIT_PULL="${WATCHDOG_SKIP_GIT_PULL:-0}"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

run_as_repo_user() {
  local repo_owner
  repo_owner="$(stat -c '%U' "$PROJECT_ROOT")"
  if [[ "$(id -un)" == "$repo_owner" ]]; then
    "$@"
  else
    sudo -u "$repo_owner" "$@"
  fi
}

prepare_repo_for_pull() {
  if [[ -d "$PROJECT_ROOT/.git" ]]; then
    run_as_repo_user git -C "$PROJECT_ROOT" config core.filemode false
  fi
}

maybe_pull_latest() {
  local before_commit
  local after_commit

  if [[ "$SKIP_GIT_PULL" == "1" ]]; then
    echo "Skipping git pull because WATCHDOG_SKIP_GIT_PULL=1."
    return
  fi

  if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
    echo "No git repository found at $PROJECT_ROOT. Reinstalling local files only."
    return
  fi

  before_commit="$(run_as_repo_user git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  prepare_repo_for_pull

  echo "Checking GitHub for watchdog updates..."
  if ! run_as_repo_user git -C "$PROJECT_ROOT" pull --ff-only; then
    echo
    echo "Git pull failed. If this box has local changes, use a clean clone or run:"
    echo "  watchdog-update"
    exit 1
  fi

  after_commit="$(run_as_repo_user git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

  if [[ "$before_commit" == "$after_commit" ]]; then
    echo "Watchdog code already current at commit $after_commit."
  else
    echo "Watchdog code updated from $before_commit to $after_commit."
  fi
}

main() {
  require_root
  maybe_pull_latest
  cd "$PROJECT_ROOT"
  bash "$SCRIPT_DIR/install_watchdog.sh"
  bash "$SCRIPT_DIR/restart_watchdog_services.sh"

  echo
  echo "Verification:"
  grep -n "git_commit" /opt/va-connect-watchdog/build-info.json || true
  grep -n "PC Stats - Last 24 Hours" /opt/va-connect-watchdog/va_connect_watchdog_web.py || true
  grep -n "metrics.jsonl" /opt/va-connect-watchdog/va_connect_watchdog_web.py || true
  systemctl status va-connect-site-watchdog.service --no-pager || true
  systemctl status va-connect-watchdog-web.service --no-pager || true
  ls -l /var/log/va-connect-site-watchdog/metrics.jsonl || true

  cat <<EOF

Update complete.
Open the page and hard refresh it:
  Ctrl+Shift+R

Default URL:
  http://localhost/
EOF
}

main "$@"
