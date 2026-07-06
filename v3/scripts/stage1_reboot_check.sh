#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-before}"

show_before() {
  echo "== Before reboot =="
  systemctl is-enabled va-watchdog
  systemctl status va-watchdog --no-pager
  wget -qO- http://127.0.0.1:9110/api/status | python3 -m json.tool
}

show_after() {
  echo "== After reboot =="
  systemctl status va-watchdog --no-pager
  journalctl -u va-watchdog -b --no-pager | tail -n 100
  wget -qO- http://127.0.0.1:9110/api/status | python3 -m json.tool
}

case "$MODE" in
  before)
    show_before
    ;;
  after)
    show_after
    ;;
  both)
    show_before
    echo
    echo "Reboot the gateway now, then rerun:"
    echo "  ./v3/scripts/stage1_reboot_check.sh after"
    ;;
  *)
    echo "Usage: $0 [before|after|both]" >&2
    exit 1
    ;;
esac
