#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_URL="https://github.com/JW-Arentis-UK/va-connect_watchdog.git"
DEFAULT_BRANCH="master"
DEFAULT_TARGET_DIR="/opt/va-connect-watchdog"
DEFAULT_DATA_DIR="/var/lib/va-connect-v2"
SERVICE_NAME="site_watchdog.service"
WEB_SERVICE_NAME="va-connect-watchdog-web.service"
SYSTEMD_DIR="/etc/systemd/system"
USE_VENV=1

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

backup_existing_target_dir() {
  if [[ -e "$TARGET_DIR" ]] && [[ ! -d "$TARGET_DIR/.git" ]]; then
    local backup_dir="${TARGET_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    say "Backing up existing directory to $backup_dir"
    mv "$TARGET_DIR" "$backup_dir"
  fi
}

install_prereqs() {
  say "Installing prerequisites"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get -y --fix-broken install || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    python3 \
    python3-pip \
    ca-certificates

  if ! DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv; then
    say "python3-venv is unavailable; will use system Python packages"
    USE_VENV=0
  fi
}

sync_repo() {
  say "Cloning or updating repository"
  prepare_git_safe_directory
  if [[ -d "$TARGET_DIR/.git" ]]; then
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

prepare_data_dir() {
  say "Preparing data directory"
  mkdir -p "$DATA_DIR"
  chmod 755 "$DATA_DIR"
  chown_install_user "$DATA_DIR"
}

prepare_config() {
  say "Preparing config"
  local config_path="$TARGET_DIR/config.json"
  if [[ -f "$config_path" ]]; then
    echo "Keeping existing $config_path"
    return
  fi

  cat > "$config_path" <<EOF
{
  "device_id": "$(hostname -s)",
  "data_dir": "$DATA_DIR",
  "app_match": "va-connect",
  "wan_hosts": "1.1.1.1",
  "check_interval_seconds": 30,
  "ping_timeout_seconds": 3,
  "web_host": "0.0.0.0",
  "web_port": 8787,
  "log_level": "INFO"
}
EOF
  chown_install_user "$config_path"
}

install_python_env() {
  say "Creating Python environment"
  if [[ "$USE_VENV" -eq 1 ]] && python3 -m venv "$TARGET_DIR/.venv"; then
    "$TARGET_DIR/.venv/bin/pip" install --upgrade pip setuptools wheel
    "$TARGET_DIR/.venv/bin/pip" install fastapi uvicorn psutil
    chown_install_user "$TARGET_DIR/.venv"
    return
  fi

  rm -rf "$TARGET_DIR/.venv"
  say "Installing Python packages into system Python"
  python3 -m pip install --upgrade pip setuptools wheel --break-system-packages
  python3 -m pip install fastapi uvicorn psutil --break-system-packages
}

install_systemd_unit() {
  say "Installing systemd unit"
  local python_exec
  local uvicorn_exec

  if [[ -x "$TARGET_DIR/.venv/bin/python" ]]; then
    python_exec="$TARGET_DIR/.venv/bin/python"
    uvicorn_exec="$TARGET_DIR/.venv/bin/uvicorn"
  else
    python_exec="/usr/bin/python3"
    uvicorn_exec="/usr/bin/python3 -m uvicorn"
  fi

  cat > "$SYSTEMD_DIR/$SERVICE_NAME" <<EOF
[Unit]
Description=VA-Connect v2 site watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$TARGET_DIR
Environment=PYTHONUNBUFFERED=1
Environment=VA_CONNECT_V2_DATA_DIR=$DATA_DIR
Environment=VA_CONNECT_V2_CONFIG=$TARGET_DIR/config.json
EnvironmentFile=-$TARGET_DIR/site_watchdog.env
ExecStart=$python_exec -m tools.ubuntu.runtime.site_watchdog
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  cat > "$SYSTEMD_DIR/$WEB_SERVICE_NAME" <<EOF
[Unit]
Description=VA-Connect v2 watchdog web UI
After=network-online.target $SERVICE_NAME
Wants=network-online.target

[Service]
Type=simple
User=$INSTALL_USER
WorkingDirectory=$TARGET_DIR
Environment=PYTHONUNBUFFERED=1
Environment=VA_CONNECT_V2_DATA_DIR=$DATA_DIR
Environment=VA_CONNECT_V2_CONFIG=$TARGET_DIR/config.json
EnvironmentFile=-$TARGET_DIR/site_watchdog.env
ExecStart=$uvicorn_exec tools.ubuntu.web.app:app --host 0.0.0.0 --port 8787
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl enable "$WEB_SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
  systemctl restart "$WEB_SERVICE_NAME"
}

print_next_steps() {
  cat <<EOF

Gateway bootstrap complete.

Repository:
  $TARGET_DIR

Service:
  systemctl status site_watchdog
  systemctl status va-connect-watchdog-web
  journalctl -u site_watchdog -f
  journalctl -u va-connect-watchdog-web -f

Manual API test:
  cd $TARGET_DIR
  if [ -x .venv/bin/uvicorn ]; then
    .venv/bin/uvicorn tools.ubuntu.web.app:app --host 0.0.0.0 --port 8787
  else
    python3 -m uvicorn tools.ubuntu.web.app:app --host 0.0.0.0 --port 8787
  fi

Browser:
  http://<gateway-ip>:8787
EOF
}

main() {
  require_root
  install_prereqs
  sync_repo
  prepare_data_dir
  prepare_config
  install_python_env
  install_systemd_unit
  print_next_steps
}

main "$@"
