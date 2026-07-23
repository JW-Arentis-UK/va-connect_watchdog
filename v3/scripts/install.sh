#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${VA_WATCHDOG_INSTALL_DIR:-/opt/va-connect-watchdog-v3}"
CONFIG_DIR="${VA_WATCHDOG_CONFIG_DIR:-/etc/va-watchdog}"
DATA_DIR="${VA_WATCHDOG_DATA_DIR:-/var/lib/va-watchdog}"
APP_DIR="$INSTALL_DIR/v3"
CONFIG_PATH="$CONFIG_DIR/config.json"
SITE_NAME="${VA_WATCHDOG_SITE_NAME:-}"
ASSET_ID="${VA_WATCHDOG_ASSET_ID:-}"
ENABLE_PERSISTENT_JOURNAL="${VA_WATCHDOG_ENABLE_PERSISTENT_JOURNAL:-0}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo --preserve-env=VA_WATCHDOG_INSTALL_DIR,VA_WATCHDOG_CONFIG_DIR,VA_WATCHDOG_DATA_DIR,VA_WATCHDOG_SITE_NAME,VA_WATCHDOG_ASSET_ID,VA_WATCHDOG_ENABLE_PERSISTENT_JOURNAL "$0" "$@"
fi

log() {
  printf '[VA-Watchdog install] %s\n' "$*"
}

fail() {
  printf '[VA-Watchdog install] ERROR: %s\n' "$*" >&2
  exit 1
}

[[ -d "$APP_DIR/va_watchdog" ]] || fail "Application package was not found at $APP_DIR/va_watchdog"
[[ -f "$APP_DIR/config.example.json" ]] || fail "Example configuration is missing"
[[ -f "$APP_DIR/systemd/va-watchdog.service" ]] || fail "Main systemd unit is missing"
[[ -f "$APP_DIR/systemd/va-watchdog-feed.service" ]] || fail "Feeder systemd unit is missing"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v systemctl >/dev/null 2>&1 || fail "systemd is required"

log "Validating Python modules and example configuration"
PYTHONPATH="$APP_DIR" python3 -m compileall -q "$APP_DIR/va_watchdog"
python3 -m json.tool "$APP_DIR/config.example.json" >/dev/null

install -d -m 0755 "$CONFIG_DIR" "$DATA_DIR"
if [[ ! -f "$CONFIG_PATH" ]]; then
  install -m 0640 "$APP_DIR/config.example.json" "$CONFIG_PATH"
  log "Created $CONFIG_PATH"
else
  backup="$CONFIG_PATH.$(date -u +%Y%m%dT%H%M%SZ).install.bak"
  cp -a "$CONFIG_PATH" "$backup"
  log "Preserved existing configuration and created $backup"
fi

python3 - "$CONFIG_PATH" "$SITE_NAME" "$ASSET_ID" <<'PY'
import json
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
site_name = sys.argv[2].strip()
asset_id = sys.argv[3].strip()

with path.open("r", encoding="utf-8") as handle:
    payload = json.load(handle)
if not isinstance(payload, dict):
    raise SystemExit("configuration root must be a JSON object")

if site_name or asset_id:
    identity = payload.get("identity")
    if not isinstance(identity, dict):
        identity = {}
    if site_name:
        identity["site_name"] = site_name
    if asset_id:
        identity["asset_id"] = asset_id
    payload["identity"] = identity

temporary = path.with_suffix(path.suffix + ".install.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(temporary, 0o640)
os.replace(temporary, path)
PY

if [[ "$ENABLE_PERSISTENT_JOURNAL" == "1" ]]; then
  log "Enabling persistent journald storage (explicit installer selection)"
  install -d -m 2755 /var/log/journal
  install -d -m 0755 /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/va-watchdog-persistent.conf <<'EOF'
[Journal]
Storage=persistent
EOF
  systemd-tmpfiles --create --prefix /var/log/journal || true
  systemctl restart systemd-journald
  journalctl --flush || true
fi

install -m 0644 "$APP_DIR/systemd/va-watchdog.service" /etc/systemd/system/va-watchdog.service
install -m 0644 "$APP_DIR/systemd/va-watchdog-feed.service" /etc/systemd/system/va-watchdog-feed.service
systemctl daemon-reload
systemctl enable va-watchdog-feed.service va-watchdog.service
systemctl restart va-watchdog-feed.service
systemctl restart va-watchdog.service

sleep 2
systemctl is-active --quiet va-watchdog-feed.service || fail "va-watchdog-feed.service did not start"
systemctl is-active --quiet va-watchdog.service || fail "va-watchdog.service did not start"

log "Installed VA-Connect Watchdog"
log "Configuration: $CONFIG_PATH"
log "Data: $DATA_DIR"
log "Main service: active"
log "Hardware feeder service: active (hardware feed remains controlled by configuration)"
log "Web: http://<gateway-ip>:9110/"
