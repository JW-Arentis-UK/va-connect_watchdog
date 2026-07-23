#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${VA_WATCHDOG_REPO_URL:-https://github.com/JW-Arentis-UK/va-connect_watchdog.git}"
REPO_REF="${VA_WATCHDOG_REPO_REF:-codex/gui-refresh}"
INSTALL_DIR="${VA_WATCHDOG_INSTALL_DIR:-/opt/va-connect-watchdog-v3}"
SITE_NAME="${VA_WATCHDOG_SITE_NAME:-}"
ASSET_ID="${VA_WATCHDOG_ASSET_ID:-}"
ENABLE_PERSISTENT_JOURNAL="${VA_WATCHDOG_ENABLE_PERSISTENT_JOURNAL:-}"
NON_INTERACTIVE=0

usage() {
  cat <<'EOF'
Install VA-Connect Watchdog on Ubuntu 22.04.

Usage:
  bash install_v3_gateway.sh [options]

Options:
  --site-name NAME       Operator-facing site name, for example Ellingers
  --asset-id ID          Optional physical gateway asset ID
  --ref BRANCH           Git branch (default: codex/gui-refresh)
  --repo URL             Git repository URL
  --install-dir PATH     Checkout path (default: /opt/va-connect-watchdog-v3)
  --persistent-journal   Enable persistent journald for post-crash evidence
  --no-persistent-journal
                         Do not change journald persistence
  --non-interactive      Do not prompt; use supplied options/environment
  -h, --help             Show this help

Environment variables with the VA_WATCHDOG_ prefix may also set these values.
Hardware watchdog feeding is not enabled automatically.
EOF
}

log() {
  printf '\n[VA-Watchdog] %s\n' "$*"
}

fail() {
  printf '\n[VA-Watchdog] ERROR: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --site-name)
      [[ $# -ge 2 ]] || fail "--site-name requires a value"
      SITE_NAME="$2"
      shift 2
      ;;
    --asset-id)
      [[ $# -ge 2 ]] || fail "--asset-id requires a value"
      ASSET_ID="$2"
      shift 2
      ;;
    --ref)
      [[ $# -ge 2 ]] || fail "--ref requires a value"
      REPO_REF="$2"
      shift 2
      ;;
    --repo)
      [[ $# -ge 2 ]] || fail "--repo requires a value"
      REPO_URL="$2"
      shift 2
      ;;
    --install-dir)
      [[ $# -ge 2 ]] || fail "--install-dir requires a value"
      INSTALL_DIR="$2"
      shift 2
      ;;
    --persistent-journal)
      ENABLE_PERSISTENT_JOURNAL=1
      shift
      ;;
    --no-persistent-journal)
      ENABLE_PERSISTENT_JOURNAL=0
      shift
      ;;
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
  SUDO=()
else
  command -v sudo >/dev/null 2>&1 || fail "sudo is required"
  SUDO=(sudo)
  "${SUDO[@]}" -v
fi

[[ -r /etc/os-release ]] || fail "This installer requires Ubuntu with systemd"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || fail "Unsupported operating system: ${PRETTY_NAME:-unknown}"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"
command -v apt-get >/dev/null 2>&1 || fail "apt-get is required"

if [[ "$NON_INTERACTIVE" -eq 0 && -t 0 ]]; then
  if [[ -z "$SITE_NAME" ]]; then
    read -r -p "Site name (for example Ellingers): " SITE_NAME
  fi
  if [[ -z "$ASSET_ID" ]]; then
    read -r -p "Asset ID (optional, press Enter to skip): " ASSET_ID
  fi
  if [[ -z "$ENABLE_PERSISTENT_JOURNAL" ]]; then
    read -r -p "Enable persistent system journal for crash evidence? [Y/n]: " answer
    case "${answer:-Y}" in
      [Nn]*) ENABLE_PERSISTENT_JOURNAL=0 ;;
      *) ENABLE_PERSISTENT_JOURNAL=1 ;;
    esac
  fi
fi

ENABLE_PERSISTENT_JOURNAL="${ENABLE_PERSISTENT_JOURNAL:-0}"
[[ "$ENABLE_PERSISTENT_JOURNAL" =~ ^[01]$ ]] || fail "Persistent journal selection must be 0 or 1"

log "Installing Ubuntu runtime and diagnostic packages"
"${SUDO[@]}" apt-get update
"${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git \
  python3 \
  smartmontools \
  lm-sensors \
  sysstat \
  ethtool \
  iproute2 \
  iputils-ping \
  util-linux \
  procps \
  pciutils \
  curl \
  wget

if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]]; then
  fail "$INSTALL_DIR exists but is not a Git checkout; move it aside and run again"
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
  log "Checking existing checkout at $INSTALL_DIR"
  dirty="$("${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" status --porcelain --untracked-files=no)"
  [[ -z "$dirty" ]] || fail "Tracked local changes exist in $INSTALL_DIR; preserve or commit them before installation"
  "${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
else
  log "Cloning repository into $INSTALL_DIR"
  "${SUDO[@]}" git clone "$REPO_URL" "$INSTALL_DIR"
fi

log "Selecting validated source ref $REPO_REF"
"${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" \
  fetch --prune origin "+refs/heads/$REPO_REF:refs/remotes/origin/$REPO_REF"
current_commit="$("${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" rev-parse HEAD)"
target_commit="$("${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" rev-parse "refs/remotes/origin/$REPO_REF")"
if [[ "$current_commit" != "$target_commit" ]]; then
  backup_branch="backup/pre-full-install-$(date -u +%Y%m%dT%H%M%SZ)"
  "${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" branch "$backup_branch" "$current_commit"
  log "Preserved previous checkout as $backup_branch"
fi
"${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" \
  checkout -B "$REPO_REF" "refs/remotes/origin/$REPO_REF"
"${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" \
  branch --set-upstream-to="origin/$REPO_REF" "$REPO_REF"

log "Installing services and configuration"
"${SUDO[@]}" env \
  VA_WATCHDOG_INSTALL_DIR="$INSTALL_DIR" \
  VA_WATCHDOG_SITE_NAME="$SITE_NAME" \
  VA_WATCHDOG_ASSET_ID="$ASSET_ID" \
  VA_WATCHDOG_ENABLE_PERSISTENT_JOURNAL="$ENABLE_PERSISTENT_JOURNAL" \
  "$INSTALL_DIR/v3/scripts/install.sh"

log "Running post-install verification"
main_state="$(systemctl is-active va-watchdog.service 2>/dev/null || true)"
feed_state="$(systemctl is-active va-watchdog-feed.service 2>/dev/null || true)"
main_enabled="$(systemctl is-enabled va-watchdog.service 2>/dev/null || true)"
feed_enabled="$(systemctl is-enabled va-watchdog-feed.service 2>/dev/null || true)"
api="$(curl --silent --show-error --max-time 10 http://127.0.0.1:9110/api/healthz || true)"
identity="$(curl --silent --show-error --max-time 10 http://127.0.0.1:9110/api/identity || true)"
journal_status="Not enabled"
if [[ -f /etc/systemd/journald.conf.d/va-watchdog-persistent.conf ]]; then
  journal_status="Enabled by VA-Watchdog installer"
elif [[ -d /var/log/journal ]]; then
  journal_status="Available (existing system configuration)"
fi
gateway_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
commit="$("${SUDO[@]}" git -c "safe.directory=$INSTALL_DIR" -C "$INSTALL_DIR" rev-parse --short HEAD)"

printf '\n============================================================\n'
printf 'VA-Connect Watchdog installation complete\n'
printf '============================================================\n'
printf 'Build:              %s (%s)\n' "$commit" "$REPO_REF"
printf 'Site name:          %s\n' "${SITE_NAME:-Not configured - set it in Settings}"
printf 'Asset ID:           %s\n' "${ASSET_ID:--}"
printf 'Main service:       %s / %s\n' "$main_state" "$main_enabled"
printf 'Feeder service:     %s / %s\n' "$feed_state" "$feed_enabled"
printf 'Persistent journal: %s\n' "$journal_status"
printf 'SMART tool:         %s\n' "$(command -v smartctl || echo missing)"
printf 'Web interface:      http://%s:9110/\n' "${gateway_ip:-<gateway-ip>}"
printf 'Health API:         %s\n' "${api:-No response}"
printf 'Identity API:       %s\n' "${identity:-No response}"
printf '\nA new installation leaves hardware watchdog feeding disabled. Existing\n'
printf 'hardware-feed configuration is preserved. Configure and test it from\n'
printf 'the Watchdog page before relying on automatic hardware reset.\n'

[[ "$main_state" == "active" ]] || fail "Main service verification failed"
[[ "$feed_state" == "active" ]] || fail "Feeder service verification failed"
[[ -n "$api" ]] || fail "Health API did not respond"
