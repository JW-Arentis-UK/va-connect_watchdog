#!/usr/bin/env bash

set -euo pipefail

DEFAULT_REPO_URL="https://github.com/JW-Arentis-UK/va-connect_watchdog.git"
DEFAULT_BRANCH="master"
DEFAULT_TARGET_DIR="$HOME/Desktop/va-connect-watchdog"
MIN_ROOT_FREE_MB="${MIN_ROOT_FREE_MB:-2048}"
MIN_TARGET_PARENT_FREE_MB="${MIN_TARGET_PARENT_FREE_MB:-1024}"
MIN_VAR_LOG_FREE_MB="${MIN_VAR_LOG_FREE_MB:-512}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_ed25519}"
SSH_COMMENT="${SSH_COMMENT:-$(hostname)-gateway-watchdog}"

REPO_URL="${1:-$DEFAULT_REPO_URL}"
BRANCH="${2:-$DEFAULT_BRANCH}"
TARGET_DIR="${3:-$DEFAULT_TARGET_DIR}"
TARGET_PARENT="$(dirname "$TARGET_DIR")"
NEEDS_SSH=0

if [[ "$REPO_URL" == git@* || "$REPO_URL" == ssh://* ]]; then
  NEEDS_SSH=1
fi

usage() {
  cat <<EOF
Usage: $0 [github_repo_url] [branch] [target_dir]

Examples:
  $0
  $0 https://github.com/JW-Arentis-UK/va-connect_watchdog.git
  $0 git@github.com:JW-Arentis-UK/va-connect_watchdog.git master ~/Desktop/va-connect-watchdog
EOF
}

say() {
  printf '\n==> %s\n' "$1"
}

warn() {
  printf 'WARNING: %s\n' "$1"
}

fail() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

command_missing() {
  ! command -v "$1" >/dev/null 2>&1
}

require_supported_os() {
  [[ -r /etc/os-release ]] || fail "/etc/os-release not found. This script expects Ubuntu or Debian."
  # shellcheck disable=SC1091
  source /etc/os-release

  case "${ID:-}" in
    ubuntu|debian)
      ;;
    *)
      fail "Unsupported distro: ${PRETTY_NAME:-unknown}. This bootstrap expects Ubuntu or Debian."
      ;;
  esac
}

require_basics() {
  command_missing sudo && fail "sudo is required."
  command_missing apt-get && fail "apt-get is required."
  command_missing systemctl && fail "systemctl is required."
}

free_mb_for_path() {
  local path="$1"
  df -Pm "$path" 2>/dev/null | awk 'NR==2 { print $4 }'
}

check_space_threshold() {
  local path="$1"
  local min_mb="$2"
  local label="$3"
  local free_mb

  free_mb="$(free_mb_for_path "$path")"
  if [[ -z "$free_mb" ]]; then
    warn "Could not read free space for $label ($path)."
    return 0
  fi

  printf '  %-26s %8s MB free\n' "$label" "$free_mb"
  if (( free_mb < min_mb )); then
    fail "$label has only ${free_mb}MB free. Need at least ${min_mb}MB before install."
  fi
}

report_drives() {
  say "Checking disks and free space"
  if command -v lsblk >/dev/null 2>&1; then
    lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
  else
    warn "lsblk not available; skipping block-device inventory."
  fi

  mkdir -p "$TARGET_PARENT"

  check_space_threshold "/" "$MIN_ROOT_FREE_MB" "Root filesystem"
  check_space_threshold "$TARGET_PARENT" "$MIN_TARGET_PARENT_FREE_MB" "Target parent"

  if [[ -d /var/log ]]; then
    check_space_threshold "/var/log" "$MIN_VAR_LOG_FREE_MB" "/var/log"
  fi

  if [[ -d /mnt/storage ]]; then
    local storage_free
    storage_free="$(free_mb_for_path /mnt/storage)"
    if [[ -n "$storage_free" ]]; then
      printf '  %-26s %8s MB free\n' "/mnt/storage" "$storage_free"
    fi
  else
    warn "/mnt/storage not present. That is fine unless this gateway records locally."
  fi
}

install_prereqs() {
  local packages

  packages=(
    git
    python3
    python3-venv
    python3-distutils
    curl
    wget
    ca-certificates
    procps
    iputils-ping
    net-tools
    jq
    smartmontools
    edac-utils
  )

  if (( NEEDS_SSH == 1 )); then
    packages+=(openssh-client)
  fi

  say "Installing required packages"
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

report_runtime_prereqs() {
  say "Checking installed tools"
  local tools
  tools=(git python3 systemctl pgrep ping jq curl wget)
  if (( NEEDS_SSH == 1 )); then
    tools+=(ssh ssh-keygen)
  fi

  local tool
  for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '  %-18s %s\n' "$tool" "$(command -v "$tool")"
    else
      fail "Expected tool missing after install: $tool"
    fi
  done
}

report_gateway_apps() {
  say "Checking gateway app baselines"

  if [[ -x /home/vsuser/vsgwgui/vsgwgui ]]; then
    echo "  VA-Connect launcher found at /home/vsuser/vsgwgui/vsgwgui"
  else
    warn "VA-Connect launcher not found at /home/vsuser/vsgwgui/vsgwgui. Update /opt/va-connect-watchdog/va-connect.env after install."
  fi

  if systemctl list-unit-files 2>/dev/null | grep -q '^teamviewerd\.service'; then
    echo "  teamviewerd.service is installed"
  else
    warn "teamviewerd.service not found. Install TeamViewer if remote support depends on it."
  fi
}

ensure_ssh_key() {
  if (( NEEDS_SSH != 1 )); then
    return 0
  fi

  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"

  if [[ ! -f "$SSH_KEY_PATH" ]]; then
    say "Creating SSH key for GitHub access"
    ssh-keygen -t ed25519 -C "$SSH_COMMENT" -f "$SSH_KEY_PATH" -N ""
  fi

  echo
  echo "GitHub public key for this gateway:"
  cat "${SSH_KEY_PATH}.pub"
  echo
}

check_github_access() {
  if (( NEEDS_SSH != 1 )); then
    return 0
  fi

  say "Checking GitHub SSH access"
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -T git@github.com >/tmp/watchdog-github-auth.txt 2>&1; then
    return 0
  fi

  if grep -qi "successfully authenticated" /tmp/watchdog-github-auth.txt; then
    return 0
  fi

  cat /tmp/watchdog-github-auth.txt
  fail "GitHub SSH access is not ready. Add the key above to GitHub, then rerun this script."
}

sync_repo() {
  say "Cloning or updating watchdog repo"
  mkdir -p "$TARGET_PARENT"

  if [[ -d "$TARGET_DIR/.git" ]]; then
    echo "  Repo already exists at $TARGET_DIR"
    git -C "$TARGET_DIR" remote set-url origin "$REPO_URL"
    git -C "$TARGET_DIR" fetch origin "$BRANCH"
    git -C "$TARGET_DIR" checkout "$BRANCH"
    git -C "$TARGET_DIR" pull --ff-only origin "$BRANCH"
  else
    git clone --branch "$BRANCH" "$REPO_URL" "$TARGET_DIR"
  fi
}

install_watchdog() {
  say "Installing watchdog services"
  cd "$TARGET_DIR/tools/ubuntu"
  chmod +x ./*.sh
  sudo bash ./install_watchdog.sh
}

print_next_steps() {
  cat <<EOF

Gateway bootstrap complete.

Repo:
  $REPO_URL

Installed checkout:
  $TARGET_DIR

Live runtime:
  /opt/va-connect-watchdog

Next checks:
  sudo systemctl status va-connect-site-watchdog.service --no-pager
  sudo systemctl status va-connect-watchdog-web.service --no-pager
  sudo nano /opt/va-connect-watchdog/va-connect.env
  sudo nano /opt/va-connect-watchdog/site-watchdog.json

Update command after first install:
  watchdog-update
EOF
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    exit 0
  fi

  require_supported_os
  require_basics
  report_drives
  install_prereqs
  report_runtime_prereqs
  report_gateway_apps
  ensure_ssh_key
  check_github_access
  sync_repo
  install_watchdog
  print_next_steps
}

main "$@"
