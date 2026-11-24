#!/usr/bin/env bash
# One entry point for new, existing and partially installed Ubuntu V3 gateways.
set -Eeuo pipefail

validate_platform() {
  [[ "$1" == ubuntu && "$2" == 22.04 && "$3" == amd64 ]] || {
    echo "This setup supports Ubuntu 22.04 amd64 gateways only." >&2
    return 1
  }
}

check_legacy_services() {
  local unit
  for unit in va-connect-site-watchdog.service va-connect-watchdog.service va-connect-watchdog-web.service; do
    if systemctl is-active --quiet "$unit" || systemctl is-enabled --quiet "$unit"; then
      echo "Legacy V1/V2 service detected: $unit. An attended migration is required; nothing has been removed." >&2
      return 1
    fi
  done
}

run_installer() {
  local installer="$1" sources="$2" apt_config="$3" existing="$4"
  shift 4
  local options=(--persistent-journal)
  # Existing identity/settings are retained unless explicitly supplied by the caller.
  if [[ "$existing" == 1 ]]; then
    options=(--non-interactive)
  fi
  "${SUDO[@]}" env APT_CONFIG="$apt_config" \
    VA_WATCHDOG_APT_SOURCES="$sources" \
    VA_WATCHDOG_INSTALL_DIR="$INSTALL_DIR" \
    VA_WATCHDOG_SITE_NAME="${VA_WATCHDOG_SITE_NAME:-}" \
    VA_WATCHDOG_ASSET_ID="${VA_WATCHDOG_ASSET_ID:-}" \
    bash "$installer" "${options[@]}" "$@"
}

main() {
  if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    echo "Usage: bash setup_gateway.sh [installer options]"
    echo "Installs, updates or repairs V3 on Ubuntu 22.04 amd64."
    echo "New installs prompt for identity and enable persistent crash logging."
    echo "Existing installs preserve identity and journal settings."
    echo "Options include --site-name NAME, --asset-id ID, --non-interactive."
    echo "V1/V2 migrations and other operating systems need separate setup."
    return
  fi
  # Keep source and checkout selection consistent with this published entry point.
  local arg
  for arg in "$@"; do
    case "$arg" in
      --repo|--ref|--install-dir|--apt-sources)
        echo "$arg is not supported by this gateway setup entry point." >&2; return 1 ;;
    esac
  done
  source /etc/os-release
  validate_platform "${ID:-}" "${VERSION_ID:-}" "$(dpkg --print-architecture)"
  command -v systemctl >/dev/null
  [[ -r /usr/share/keyrings/ubuntu-archive-keyring.gpg ]] || {
    echo "Ubuntu archive signing keyring is missing." >&2; return 1;
  }
  INSTALL_DIR="${VA_WATCHDOG_INSTALL_DIR:-/opt/va-connect-watchdog-v3}"
  [[ "$INSTALL_DIR" == /* ]] || { echo "Installation path must be absolute." >&2; return 1; }
  SUDO=()
  if [[ "$EUID" -ne 0 ]]; then SUDO=(sudo); sudo -v; fi
  check_legacy_services
  local existing=0
  if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR/.git" ]]; then
    echo "$INSTALL_DIR exists but is not a Git checkout; preserve it before installing." >&2
    return 1
  fi
  if [[ -d "$INSTALL_DIR/.git" ]]; then
    existing=1
    echo "Existing V3 checkout detected: updating or repairing with the current installer."
  else
    echo "New V3 installation."
  fi
  # Also preserve settings after a partial installation or lost checkout.
  if "${SUDO[@]}" test -f /etc/va-watchdog/config.json; then existing=1; fi
  work_dir=$(mktemp -d)
  trap 'rm -rf -- "$work_dir"' EXIT
  chmod 755 "$work_dir"
  cat > "$work_dir/ubuntu.list" <<'EOF'
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://security.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
EOF
  cat > "$work_dir/apt.conf" <<EOF
Dir::Etc::sourcelist "$work_dir/ubuntu.list";
Dir::Etc::sourceparts "-";
APT::Update::Error-Mode "any";
EOF
  "${SUDO[@]}" env APT_CONFIG="$work_dir/apt.conf" apt-get update
  "${SUDO[@]}" env APT_CONFIG="$work_dir/apt.conf" DEBIAN_FRONTEND=noninteractive \
    apt-get install -y ca-certificates wget git python3-venv
  wget -O "$work_dir/install_v3_gateway.sh" \
    https://raw.githubusercontent.com/JW-Arentis-UK/va-connect_watchdog/codex/gui-refresh/install_v3_gateway.sh
  # Do not inherit a caller's alternative repo/ref when selecting this release.
  export VA_WATCHDOG_REPO_URL=https://github.com/JW-Arentis-UK/va-connect_watchdog.git
  export VA_WATCHDOG_REPO_REF=codex/gui-refresh
  run_installer "$work_dir/install_v3_gateway.sh" "$work_dir/ubuntu.list" "$work_dir/apt.conf" "$existing" "$@"
  echo "Installed build:"
  cat "$INSTALL_DIR/v3/build.json"
  echo "Open http://<gateway-ip>:9110/ and use the configured Ubuntu operator account (default: vsuser)."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
