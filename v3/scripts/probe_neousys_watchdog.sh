#!/usr/bin/env bash
set -u

echo "===== Platform ====="
cat /sys/class/dmi/id/product_name 2>/dev/null || true
uname -a

echo "===== Neousys module ====="
lsmod | grep '^wdt_dio ' || true
modinfo wdt_dio 2>&1 || true

echo "===== Neousys device ====="
ls -l /dev/wdt_dio 2>&1 || true

echo "===== Neousys library ====="
ls -l /usr/local/lib/va-watchdog/vendor/libwdt_dio.so 2>&1 || true
sha256sum /usr/local/lib/va-watchdog/vendor/libwdt_dio.so 2>&1 || true

echo "===== VA-Connect configuration ====="
python3 - <<'PY'
import json
from pathlib import Path

path = Path("/etc/va-watchdog/config.json")
try:
    config = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"Configuration unavailable: {exc}")
else:
    print(json.dumps(config.get("hardware_watchdog", {}), indent=2, sort_keys=True))
PY

echo "===== Independent feeder ====="
systemctl status va-watchdog-feed.service --no-pager -l 2>&1 || true
cat /var/lib/va-watchdog/hardware-watchdog-feed.json 2>&1 || true

echo "===== Conflicting watchdog services ====="
for unit in watchdog.service wd_keepalive.service; do
  printf '%s: ' "$unit"
  systemctl is-active "$unit" 2>/dev/null || true
done

echo "===== Kernel messages ====="
dmesg | grep -Ei 'wdt_dio|watchdog|reset' | tail -80 || true
