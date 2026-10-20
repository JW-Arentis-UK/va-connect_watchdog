#!/usr/bin/env bash
# Enable the Raspberry Pi's kernel watchdog under systemd PID 1.
set -Eeuo pipefail

CONF_DIR=/etc/systemd/system.conf.d
CONF_FILE="$CONF_DIR/90-va-watchdog-pi.conf"
DEVICE=/dev/watchdog0
STATE=/sys/class/watchdog/watchdog0/state
IDENTITY=/sys/class/watchdog/watchdog0/identity

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo 'Run this script with sudo.' >&2; exit 1; }
[[ -r /proc/device-tree/model ]] && grep -aq 'Raspberry Pi' /proc/device-tree/model || {
  echo 'This script is only for Raspberry Pi hardware.' >&2; exit 1;
}
[[ -c "$DEVICE" && -r "$STATE" ]] || { echo "$DEVICE is unavailable." >&2; exit 1; }
command -v systemctl >/dev/null || { echo 'systemctl is required.' >&2; exit 1; }

runtime_usec=$(systemctl show -p RuntimeWatchdogUSec --value)
state=$(cat "$STATE")
echo "Device: $DEVICE ($(cat "$IDENTITY"))"
echo "Before: systemd RuntimeWatchdogUSec=$runtime_usec; device state=$state"
if [[ "$runtime_usec" =~ ^[0-9]+$ && "$runtime_usec" -gt 0 ]]; then
  [[ "$state" == active ]] && { echo 'Systemd hardware watchdog is already active.'; exit 0; }
  echo 'Systemd is configured for a watchdog, but the device is not active. Investigate before changing ownership.' >&2
  exit 1
fi
[[ "$state" == inactive ]] || { echo 'The watchdog is already active under another owner; leaving it unchanged.' >&2; exit 1; }

install -d -m 0755 "$CONF_DIR"
backup=''
if [[ -e "$CONF_FILE" ]]; then
  backup="$CONF_FILE.$(date -u +%Y%m%dT%H%M%SZ).bak"
  cp -a "$CONF_FILE" "$backup"
fi
temporary=$(mktemp "$CONF_DIR/.va-watchdog-pi.XXXXXX")
printf '[Manager]\nRuntimeWatchdogSec=15s\nWatchdogDevice=/dev/watchdog0\n' > "$temporary"
chmod 0644 "$temporary"
mv -f "$temporary" "$CONF_FILE"

rollback() {
  if [[ -n "$backup" ]]; then cp -a "$backup" "$CONF_FILE"; else rm -f "$CONF_FILE"; fi
  systemctl daemon-reexec || true
}
if ! systemctl daemon-reexec; then
  rollback
  echo 'Could not reload systemd; previous configuration restored.' >&2
  exit 1
fi
sleep 3
runtime_usec=$(systemctl show -p RuntimeWatchdogUSec --value)
state=$(cat "$STATE")
if [[ ! "$runtime_usec" =~ ^[0-9]+$ || "$runtime_usec" -eq 0 || "$state" != active ]]; then
  rollback
  echo "Hardware watchdog did not activate (systemd=$runtime_usec, state=$state); previous configuration restored." >&2
  exit 1
fi
echo "Pi hardware watchdog active: systemd requests ${runtime_usec}µs; kernel timeout $(cat /sys/class/watchdog/watchdog0/timeout)s."
