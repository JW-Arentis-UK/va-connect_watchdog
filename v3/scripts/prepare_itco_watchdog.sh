#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "VA-Connect Watchdog V3 - automatic Intel TCO hardware watchdog prepare"
echo "Started: $(date -Is)"
echo
echo "This performs the recommended POC-451VTC setup:"
echo "  1. Load and persist the Intel TCO watchdog driver"
echo "  2. Stop and disable Ubuntu's legacy watchdog.service"
echo "  3. Reinstall/reload the VA-Connect systemd unit"
echo "  4. Restart va-watchdog so it owns /dev/watchdog0"
echo

echo "== Step 1: load and persist Intel TCO =="
/bin/bash "$APP_DIR/scripts/setup_itco_watchdog.sh"
echo

echo "== Step 2: disable legacy watchdog.service =="
if systemctl list-unit-files watchdog.service >/dev/null 2>&1; then
  systemctl disable --now watchdog.service || true
else
  echo "watchdog.service is not installed as a systemd unit."
fi
systemctl status watchdog.service --no-pager || true
echo

echo "== Step 3: current watchdog device status =="
ls -l /dev/watchdog* 2>/dev/null || true
if command -v wdctl >/dev/null 2>&1 && [ -e /dev/watchdog0 ]; then
  wdctl /dev/watchdog0 || true
else
  echo "wdctl unavailable or /dev/watchdog0 is not present yet."
fi
echo

echo "== Step 4: reinstall/reload VA-Connect service =="
/bin/bash "$APP_DIR/scripts/install.sh"
echo

echo "== Step 5: final service status =="
systemctl status va-watchdog.service --no-pager || true
echo
echo "Finished: $(date -Is)"
