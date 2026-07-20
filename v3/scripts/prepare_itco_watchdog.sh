#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "VA-Connect Watchdog - automatic Intel TCO hardware watchdog prepare"
echo "Started: $(date -Is)"
echo
echo "This performs the recommended POC-451VTC setup:"
echo "  1. Load and persist the Intel TCO watchdog driver"
echo "  2. Stop, disable, mask, and remove Ubuntu's legacy watchdog daemon if present"
echo "  3. Write the VA-Connect hardware watchdog config"
echo "  4. Reinstall/reload the VA-Connect systemd unit"
echo "  5. Restart va-watchdog so it owns /dev/watchdog0"
echo

echo "== Step 1: load and persist Intel TCO =="
/bin/bash "$APP_DIR/scripts/setup_itco_watchdog.sh"
echo

echo "== Step 2: remove legacy watchdog daemon ownership =="
stop_disable_mask_unit() {
  local unit="$1"
  if systemctl list-unit-files --type=service --all | awk '{print $1}' | grep -qx "$unit"; then
    echo "Stopping/disabling/masking $unit"
    systemctl stop "$unit" || true
    systemctl disable "$unit" || true
    systemctl mask "$unit" || true
  else
    echo "$unit is not installed as a systemd unit."
  fi
}

stop_disable_mask_unit watchdog.service
stop_disable_mask_unit wd_keepalive.service

if command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' watchdog 2>/dev/null | grep -q "install ok installed"; then
  echo "Purging Ubuntu watchdog package"
  DEBIAN_FRONTEND=noninteractive apt-get purge -y watchdog || true
else
  echo "Ubuntu watchdog package is not installed."
fi
systemctl status watchdog.service --no-pager || true
systemctl status wd_keepalive.service --no-pager || true
echo

echo "== Step 3: current watchdog device status =="
ls -l /dev/watchdog* 2>/dev/null || true
if command -v wdctl >/dev/null 2>&1 && [ -e /dev/watchdog0 ]; then
  wdctl /dev/watchdog0 || true
else
  echo "wdctl unavailable or /dev/watchdog0 is not present yet."
fi
echo

echo "== Step 4: enable VA-Connect hardware watchdog config =="
python3 - <<'PY'
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

path = Path("/etc/va-watchdog/config.json")
path.parent.mkdir(parents=True, exist_ok=True)
payload = {}
if path.exists():
    payload = json.loads(path.read_text(encoding="utf-8"))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    shutil.copy2(path, path.with_name(f"{path.name}.{stamp}.bak"))

payload.setdefault("hardware_watchdog", {})
payload["hardware_watchdog"].update({
    "enabled": True,
    "device": "/dev/watchdog0",
    "feed_interval_seconds": 10,
    "timeout_seconds": 30,
})

tmp = path.with_suffix(path.suffix + ".tmp")
tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp.replace(path)
print("Updated /etc/va-watchdog/config.json: hardware_watchdog.enabled=true")
PY
echo

echo "== Step 5: reinstall/reload VA-Connect service =="
/bin/bash "$APP_DIR/scripts/install.sh"
echo

echo "== Step 6: final service status =="
systemctl status va-watchdog.service --no-pager || true
echo

echo "== Step 7: final watchdog verification =="
systemctl is-active watchdog.service || true
systemctl is-enabled watchdog.service || true
systemctl is-active wd_keepalive.service || true
systemctl is-enabled wd_keepalive.service || true
ls -l /dev/watchdog* 2>/dev/null || true
if command -v wdctl >/dev/null 2>&1 && [ -e /dev/watchdog0 ]; then
  wdctl /dev/watchdog0 || true
fi
echo

echo "Finished: $(date -Is)"
