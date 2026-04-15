#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_URL="https://github.com/JW-Arentis-UK/va-connect_watchdog.git"
DEFAULT_BRANCH="master"
DEFAULT_TARGET_DIR="/opt/va-connect-watchdog"
DEFAULT_DATA_DIR="/var/lib/va-connect-v2"
SERVICE_NAME="site_watchdog.service"
SYSTEMD_DIR="/etc/systemd/system"

REPO_URL="${1:-$DEFAULT_REPO_URL}"
BRANCH="${2:-$DEFAULT_BRANCH}"
TARGET_DIR="${3:-$DEFAULT_TARGET_DIR}"
DATA_DIR="${DATA_DIR:-$DEFAULT_DATA_DIR}"

say() {
  printf '\n==> %s\n' "$1"
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run this script with sudo or as root."
    exit 1
  fi
}

install_prereqs() {
  say "Installing prerequisites"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    git \
    python3 \
    python3-venv \
    python3-pip \
    ca-certificates
}

sync_repo() {
  say "Cloning or updating repository"
  if [[ -d "$TARGET_DIR/.git" ]]; then
    git -C "$TARGET_DIR" fetch origin "$BRANCH"
    git -C "$TARGET_DIR" checkout "$BRANCH"
    git -C "$TARGET_DIR" pull --ff-only origin "$BRANCH"
    return
  fi

  if [[ -e "$TARGET_DIR" ]] && [[ ! -d "$TARGET_DIR/.git" ]]; then
    echo "Target directory exists but is not a git checkout: $TARGET_DIR"
    exit 1
  fi

  mkdir -p "$(dirname "$TARGET_DIR")"
  git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
}

prepare_data_dir() {
  say "Preparing data directory"
  mkdir -p "$DATA_DIR"
  chmod 755 "$DATA_DIR"
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
}

install_python_env() {
  say "Creating Python environment"
  python3 -m venv "$TARGET_DIR/.venv"
  "$TARGET_DIR/.venv/bin/pip" install --upgrade pip setuptools wheel
  "$TARGET_DIR/.venv/bin/pip" install fastapi uvicorn psutil
}

install_systemd_unit() {
  say "Installing systemd unit"
  install -m 644 "$TARGET_DIR/tools/ubuntu/deploy/$SERVICE_NAME" "$SYSTEMD_DIR/$SERVICE_NAME"
  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"
}

print_next_steps() {
  cat <<EOF

Gateway bootstrap complete.

Repository:
  $TARGET_DIR

Service:
  systemctl status site_watchdog
  journalctl -u site_watchdog -f

Manual API test:
  cd $TARGET_DIR
  source .venv/bin/activate
  uvicorn tools.ubuntu.web.app:app --host 0.0.0.0 --port 8787

Browser:
  http://<gateway-ip>:80
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
