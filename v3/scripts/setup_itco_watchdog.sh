#!/usr/bin/env bash
set -euo pipefail

MODULE_CONF="/etc/modules-load.d/iTCO_wdt.conf"

echo "VA-Connect Watchdog V3 - Intel TCO hardware watchdog setup"
echo
echo "This script loads the Intel TCO watchdog driver for POC-451VTC style gateways."
echo "It does not enable VA-Connect hardware feeding in /etc/va-watchdog/config.json."
echo

if ! command -v modprobe >/dev/null 2>&1; then
  echo "modprobe is required but was not found." >&2
  exit 1
fi

echo "Loading support modules..."
sudo modprobe iTCO_vendor_support || true
sudo modprobe iTCO_wdt

echo "Persisting iTCO_wdt across reboot..."
echo "iTCO_wdt" | sudo tee "$MODULE_CONF" >/dev/null

echo
echo "Loaded modules:"
lsmod | grep -E 'iTCO|intel_pmc' || true

echo
echo "Watchdog devices:"
ls -l /dev/watchdog* 2>/dev/null || true

echo
echo "Legacy watchdog daemon:"
systemctl status watchdog --no-pager || true

echo
if command -v wdctl >/dev/null 2>&1 && [ -e /dev/watchdog0 ]; then
  echo "wdctl /dev/watchdog0:"
  sudo wdctl /dev/watchdog0 || true
else
  echo "wdctl unavailable or /dev/watchdog0 is not present."
fi

echo
echo "Kernel watchdog/TCO messages:"
dmesg | grep -Ei 'watchdog|tco' | tail -40 || true

echo
echo "Next step if /dev/watchdog0 is present and wdctl reports iTCO_wdt:"
echo "  sudo systemctl disable --now watchdog"
echo "  edit /etc/va-watchdog/config.json"
echo "  set hardware_watchdog.enabled to true"
echo "  keep hardware_watchdog.device as /dev/watchdog0"
echo "  keep hardware_watchdog.feed_interval_seconds as 10"
echo "  sudo systemctl restart va-watchdog"
