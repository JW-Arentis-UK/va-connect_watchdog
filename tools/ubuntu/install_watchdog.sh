#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

INSTALL_DIR="${INSTALL_DIR:-/opt/va-connect-watchdog}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
BUILD_INFO_TARGET="$INSTALL_DIR/build-info.json"
REPO_DIR_TARGET="$INSTALL_DIR/repo-dir.txt"
SERVICE_NAME="va-connect-watchdog.service"
TIMER_NAME="va-connect-watchdog.timer"
SITE_SERVICE_NAME="va-connect-site-watchdog.service"
WEB_SERVICE_NAME="va-connect-watchdog-web.service"
ENV_TARGET="$INSTALL_DIR/va-connect.env"
ENV_EXAMPLE_SOURCE="$SCRIPT_DIR/va-connect.env.example"
SITE_CONFIG_TARGET="$INSTALL_DIR/site-watchdog.json"
SITE_CONFIG_EXAMPLE_SOURCE="$SCRIPT_DIR/site-watchdog.json.example"

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this installer with sudo or as root."
    exit 1
  fi
}

resolve_source_repo_dir() {
  if [[ -d "$PROJECT_ROOT/.git" ]]; then
    printf '%s\n' "$PROJECT_ROOT"
    return
  fi

  if [[ -f "$REPO_DIR_TARGET" ]]; then
    local saved_repo_dir
    saved_repo_dir="$(head -n 1 "$REPO_DIR_TARGET")"
    if [[ -d "$saved_repo_dir/.git" ]]; then
      printf '%s\n' "$saved_repo_dir"
      return
    fi
  fi

  printf '%s\n' "$PROJECT_ROOT"
}

run_git_as_repo_owner() {
  local repo_dir="$1"
  shift
  local repo_owner
  repo_owner="$(stat -c '%U' "$repo_dir")"
  if [[ "$(id -un)" == "$repo_owner" ]]; then
    git -C "$repo_dir" "$@"
  else
    sudo -u "$repo_owner" git -C "$repo_dir" "$@"
  fi
}

configure_repo_for_gateway_updates() {
  local source_repo_dir
  source_repo_dir="$(resolve_source_repo_dir)"
  if [[ -d "$source_repo_dir/.git" ]]; then
    run_git_as_repo_owner "$source_repo_dir" config core.filemode false || true
  fi
}

install_files() {
  mkdir -p "$INSTALL_DIR"
  mkdir -p "$BIN_DIR"

  install -m 755 "$SCRIPT_DIR/va_connect_watchdog.sh" "$INSTALL_DIR/va_connect_watchdog.sh"
  install -m 755 "$SCRIPT_DIR/va_connect_site_watchdog.py" "$INSTALL_DIR/va_connect_site_watchdog.py"
  install -m 755 "$SCRIPT_DIR/va_connect_watchdog_web.py" "$INSTALL_DIR/va_connect_watchdog_web.py"
  install -m 755 "$SCRIPT_DIR/export_watchdog_incident.sh" "$INSTALL_DIR/export_watchdog_incident.sh"
  install -m 755 "$SCRIPT_DIR/update_watchdog.sh" "$INSTALL_DIR/update_watchdog.sh"
  install -m 755 "$SCRIPT_DIR/git_update_watchdog.sh" "$INSTALL_DIR/git_update_watchdog.sh"
  install -m 755 "$SCRIPT_DIR/restart_watchdog_services.sh" "$INSTALL_DIR/restart_watchdog_services.sh"

  cat > "$BIN_DIR/watchdog-update" <<EOF
#!/usr/bin/env bash
set -euo pipefail
bash "$INSTALL_DIR/git_update_watchdog.sh" "\$@"
EOF
  chmod 755 "$BIN_DIR/watchdog-update"

  cat > "$BIN_DIR/watchdog-restart" <<EOF
#!/usr/bin/env bash
set -euo pipefail
sudo bash "$INSTALL_DIR/restart_watchdog_services.sh" "\$@"
EOF
  chmod 755 "$BIN_DIR/watchdog-restart"

  if [[ ! -f "$ENV_TARGET" ]]; then
    install -m 644 "$ENV_EXAMPLE_SOURCE" "$ENV_TARGET"
    echo "Created $ENV_TARGET from example."
  else
    echo "Keeping existing $ENV_TARGET"
  fi

  if [[ ! -f "$SITE_CONFIG_TARGET" ]]; then
    install -m 644 "$SITE_CONFIG_EXAMPLE_SOURCE" "$SITE_CONFIG_TARGET"
    echo "Created $SITE_CONFIG_TARGET from example."
  else
    echo "Keeping existing $SITE_CONFIG_TARGET"
  fi

  install -m 644 "$SCRIPT_DIR/$SERVICE_NAME" "$SYSTEMD_DIR/$SERVICE_NAME"
  install -m 644 "$SCRIPT_DIR/$TIMER_NAME" "$SYSTEMD_DIR/$TIMER_NAME"
  install -m 644 "$SCRIPT_DIR/$SITE_SERVICE_NAME" "$SYSTEMD_DIR/$SITE_SERVICE_NAME"
  install -m 644 "$SCRIPT_DIR/$WEB_SERVICE_NAME" "$SYSTEMD_DIR/$WEB_SERVICE_NAME"

  write_build_info
}

write_build_info() {
  local git_commit="unknown"
  local git_branch="unknown"
  local git_status="unknown"
  local deployed_at
  local source_repo_dir
  deployed_at="$(date -Is)"
  source_repo_dir="$(resolve_source_repo_dir)"

  if command -v git >/dev/null 2>&1 && [[ -d "$source_repo_dir/.git" ]]; then
    git_commit="$(run_git_as_repo_owner "$source_repo_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    git_branch="$(run_git_as_repo_owner "$source_repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    if run_git_as_repo_owner "$source_repo_dir" diff --quiet --ignore-submodules HEAD -- 2>/dev/null; then
      git_status="clean"
    else
      git_status="dirty"
    fi
  fi

  cat > "$BUILD_INFO_TARGET" <<EOF
{
  "deployed_at": "$deployed_at",
  "git_branch": "$git_branch",
  "git_commit": "$git_commit",
  "git_status": "$git_status",
  "source_repo_dir": "$source_repo_dir"
}
EOF

  printf '%s\n' "$source_repo_dir" > "$REPO_DIR_TARGET"
}

enable_timer() {
  systemctl daemon-reload
  systemctl disable --now "$TIMER_NAME" || true
  systemctl stop "$SERVICE_NAME" || true
  systemctl enable --now "$SITE_SERVICE_NAME"
  systemctl enable --now "$WEB_SERVICE_NAME"
}

print_next_steps() {
  local build_commit
  build_commit="$(grep -oE '"git_commit": *"[^"]+"' "$BUILD_INFO_TARGET" | head -n1 | cut -d'"' -f4 || true)"
  cat <<EOF
Install complete.
Build: ${build_commit:-unknown}
Services: $SITE_SERVICE_NAME and $WEB_SERVICE_NAME are enabled.
Web UI: http://<encoder-ip>/
EOF
}

main() {
  require_root
  configure_repo_for_gateway_updates
  install_files
  enable_timer
  print_next_steps
}

main "$@"
