#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_URL="https://github.com/JW-Arentis-UK/va-connect_watchdog.git"
DEFAULT_BRANCH="master"
DEFAULT_TARGET_DIR="/opt/va-connect-watchdog"
DEFAULT_DATA_DIR="/var/lib/va-connect-site-watchdog"
SERVICE_NAME="site_watchdog.service"
WEB_SERVICE_NAME="va-connect-watchdog-web.service"
SYSTEMD_DIR="/etc/systemd/system"

REPO_URL="${1:-$DEFAULT_REPO_URL}"
BRANCH="${2:-$DEFAULT_BRANCH}"
TARGET_DIR="${3:-$DEFAULT_TARGET_DIR}"
DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"
INSTALL_USER="${SUDO_USER:-$(id -un)}"

say() {
  printf '\n==> %s\n' "$1"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

prepare_git_safe_directory() {
  git config --global --add safe.directory "$TARGET_DIR" >/dev/null 2>&1 || true
}

chown_install_user() {
  chown -R "$INSTALL_USER" "$1"
}

repair_known_apt_blockers() {
  # Chrome Remote Desktop can leave dpkg in a half-configured state on Ubuntu
  # hosts where adduser rejects the package's _crd_network account name.
  if dpkg -s chrome-remote-desktop >/dev/null 2>&1; then
    if ! getent passwd _crd_network >/dev/null 2>&1; then
      say "Repairing Chrome Remote Desktop system account"
      adduser --system --group --force-badname --no-create-home --home /nonexistent _crd_network >/dev/null
    fi
  fi
}

backup_existing_target_dir() {
  if [[ -e "$TARGET_DIR" ]] && [[ ! -d "$TARGET_DIR/.git" ]]; then
    local backup_dir="${TARGET_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    say "Backing up existing directory to $backup_dir"
    mv "$TARGET_DIR" "$backup_dir"
  fi
}

install_prereqs() {
  say "Installing prerequisites"
  local missing_packages=()

  repair_known_apt_blockers

  if ! command -v git >/dev/null 2>&1; then
    missing_packages+=(git)
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    missing_packages+=(python3)
  fi
  if ! dpkg -s ca-certificates >/dev/null 2>&1; then
    missing_packages+=(ca-certificates)
  fi
  if ! dpkg -s python3-venv >/dev/null 2>&1; then
    missing_packages+=(python3-venv)
  fi

  if [[ "${#missing_packages[@]}" -eq 0 ]]; then
    echo "Prerequisites already installed."
    return
  fi

  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}"
}

sync_repo() {
  say "Cloning or updating repository"
  prepare_git_safe_directory
  if [[ -d "$TARGET_DIR/.git" ]]; then
    rm -f "$TARGET_DIR/build-info.json"
    git -C "$TARGET_DIR" fetch origin "$BRANCH"
    git -C "$TARGET_DIR" checkout "$BRANCH"
    git -C "$TARGET_DIR" pull --ff-only origin "$BRANCH"
    chown_install_user "$TARGET_DIR"
    return
  fi

  backup_existing_target_dir

  mkdir -p "$(dirname "$TARGET_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
  chown_install_user "$TARGET_DIR"
}

write_build_info() {
  say "Writing build metadata"
  local git_commit="unknown"
  local git_branch="unknown"
  local git_status="unknown"
  local deployed_at
  deployed_at="$(date -Is)"

  if [[ -d "$TARGET_DIR/.git" ]]; then
    git_commit="$(git -C "$TARGET_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    git_branch="$(git -C "$TARGET_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
    if git -C "$TARGET_DIR" diff --quiet --ignore-submodules HEAD >/dev/null 2>&1; then
      git_status="clean"
    else
      git_status="dirty"
    fi
  fi

  cat > "$TARGET_DIR/build-info.json" <<EOF
{
  "deployed_at": "$deployed_at",
  "git_branch": "$git_branch",
  "git_commit": "$git_commit",
  "git_status": "$git_status",
  "source_repo_dir": "$TARGET_DIR"
}
EOF
  chown_install_user "$TARGET_DIR/build-info.json"
}

prepare_data_dir() {
  say "Preparing data directory"
  mkdir -p "$DATA_DIR"
  mkdir -p "$TARGET_DIR/logs"
  chmod 755 "$DATA_DIR" "$TARGET_DIR/logs"
  chown_install_user "$DATA_DIR"
  chown_install_user "$TARGET_DIR/logs"
}

prepare_config() {
  say "Preparing config"
  local config_path="$TARGET_DIR/site-watchdog.json"
  python3 - "$config_path" "$DATA_DIR" <<'PY'
import json
import pathlib
import socket
import sys

path = pathlib.Path(sys.argv[1])
data_dir = sys.argv[2]
current = {}
if path.exists():
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        current = {}

defaults = {
    "device_id": socket.gethostname().split(".")[0],
    "data_dir": data_dir,
    "web_bind": "0.0.0.0",
    "web_port": 80,
    "web_token": "",
}

defaults.update(current if isinstance(current, dict) else {})
defaults["data_dir"] = data_dir
defaults["web_bind"] = "0.0.0.0"
defaults["web_port"] = 80
defaults["web_token"] = ""
path.write_text(json.dumps(defaults, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
  chown_install_user "$config_path"
}

install_systemd_unit() {
  say "Installing systemd unit"
  local legacy_units=(
    "$SERVICE_NAME"
    "va-connect-site-watchdog.service"
    "va-connect-watchdog.service"
    "va-connect-watchdog.timer"
  )
  for unit in "${legacy_units[@]}"; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    rm -f "$SYSTEMD_DIR/$unit"
  done

  cat > "$SYSTEMD_DIR/$WEB_SERVICE_NAME" <<EOF
[Unit]
Description=VA-Connect watchdog web UI
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$TARGET_DIR
Environment=PYTHONUNBUFFERED=1
Environment=SITE_WATCHDOG_CONFIG=$TARGET_DIR/site-watchdog.json
ExecStart=/usr/bin/python3 $TARGET_DIR/tools/ubuntu/va_connect_watchdog_web.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$WEB_SERVICE_NAME"
}

print_next_steps() {
  cat <<EOF

Gateway bootstrap complete.

Repository:
  $TARGET_DIR

Service:
  systemctl status va-connect-watchdog-web
  journalctl -u va-connect-watchdog-web -f

Browser:
  http://<gateway-ip>/
EOF
}

main() {
  require_root
  install_prereqs
  sync_repo
  write_build_info
  prepare_data_dir
  prepare_config
  install_systemd_unit
  print_next_steps
}

main "$@"
