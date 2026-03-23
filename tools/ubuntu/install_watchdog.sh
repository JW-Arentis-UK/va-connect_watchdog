#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

INSTALL_DIR="${INSTALL_DIR:-/opt/va-connect-watchdog}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
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

install_files() {
  mkdir -p "$INSTALL_DIR"
  mkdir -p "$BIN_DIR"

  install -m 755 "$SCRIPT_DIR/va_connect_watchdog.sh" "$INSTALL_DIR/va_connect_watchdog.sh"
  install -m 755 "$SCRIPT_DIR/va_connect_site_watchdog.py" "$INSTALL_DIR/va_connect_site_watchdog.py"
  install -m 755 "$SCRIPT_DIR/va_connect_watchdog_web.py" "$INSTALL_DIR/va_connect_watchdog_web.py"
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
}

enable_timer() {
  systemctl daemon-reload
  systemctl disable --now "$TIMER_NAME" || true
  systemctl stop "$SERVICE_NAME" || true
  systemctl enable --now "$SITE_SERVICE_NAME"
  systemctl enable --now "$WEB_SERVICE_NAME"
}

print_next_steps() {
  cat <<EOF
Install complete.

Next steps:
1. Edit $ENV_TARGET with the real VA-Connect process match and start command.
2. Edit $SITE_CONFIG_TARGET with the real site IPs, RTSP target, and commands.
3. Check: systemctl status $SITE_SERVICE_NAME
4. Check: systemctl status $WEB_SERVICE_NAME
5. Check site watchdog logs: journalctl -u $SITE_SERVICE_NAME -n 50 --no-pager
6. Open the web UI on http://<encoder-ip>:8787/
7. Note: the legacy $TIMER_NAME is disabled by this installer.
8. Easy commands:
   watchdog-update
   watchdog-restart
EOF
}

main() {
  require_root
  install_files
  enable_timer
  print_next_steps
}

main "$@"
