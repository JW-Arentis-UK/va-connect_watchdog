#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_SHA256="e78018ea9c45c4bcc6ad5a3a1c42dfe092e126093d267eecacfbe7f1e8d2f658"
EXPECTED_TAR_SHA256="9c4b6033a501a605ee5ac92fe946812b7571f359a8bfbca1e442754be9476788"
VERSION="2.4.1.0"
CONFIG_PATH="${VA_WATCHDOG_CONFIG_PATH:-/etc/va-watchdog/config.json}"
LIBRARY_PATH="/usr/local/lib/va-watchdog/vendor/libwdt_dio.so"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEFAULT_BUNDLE="$SCRIPT_DIR/../vendor/neousys/WDT_DIO_202505_v2-4-1-0_Linux.zip"
ACTIVATE=0

usage() {
  cat <<'EOF'
Usage: install_neousys_wdt.sh [vendor-zip-or-tar] [--activate]

Installs the Neousys WDT_DIO driver and private library for the running kernel.
Without --activate, VA-Connect configuration is not changed and no watchdog is started.

--activate  Select the Neousys backend, enable feeding, and restart VA-Connect.
EOF
}

fail() {
  printf '[Neousys WDT install] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[Neousys WDT install] %s\n' "$*"
}

BUNDLE="$DEFAULT_BUNDLE"
if [[ $# -gt 0 && "$1" != --* ]]; then
  BUNDLE="$1"
  shift
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --activate) ACTIVATE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
  shift
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  sudo_args=("$BUNDLE")
  if [[ "$ACTIVATE" == 1 ]]; then
    sudo_args+=("--activate")
  fi
  exec sudo --preserve-env=VA_WATCHDOG_CONFIG_PATH "$0" "${sudo_args[@]}"
fi

[[ -f "$BUNDLE" ]] || fail "vendor bundle not found: $BUNDLE"
[[ "$(uname -m)" == "x86_64" ]] || fail "the supplied vendor library supports x86_64 only"
kernel="$(uname -r)"
kernel_build="/lib/modules/$kernel/build"

if ! command -v make >/dev/null 2>&1 || ! command -v gcc >/dev/null 2>&1 || [[ ! -d "$kernel_build" ]] || { [[ "$BUNDLE" == *.zip ]] && ! command -v unzip >/dev/null 2>&1; }; then
  command -v apt-get >/dev/null 2>&1 || fail "build tools or kernel headers are missing and apt-get is unavailable"
  log "Installing build tools and headers for $kernel"
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential "linux-headers-$kernel" unzip
fi

for command in sha256sum tar make gcc install depmod modprobe python3; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

actual_sha256="$(sha256sum "$BUNDLE" | awk '{print tolower($1)}')"
if [[ "$actual_sha256" != "$EXPECTED_SHA256" && "$actual_sha256" != "$EXPECTED_TAR_SHA256" ]]; then
  fail "bundle SHA256 did not match the reviewed Neousys v$VERSION package"
fi

[[ -d "$kernel_build" ]] || fail "kernel headers are missing: install linux-headers-$kernel"

workdir="$(mktemp -d /tmp/va-neousys-wdt.XXXXXX)"
cleanup() {
  rm -rf -- "$workdir"
}
trap cleanup EXIT

case "$BUNDLE" in
  *.zip)
    command -v unzip >/dev/null 2>&1 || fail "unzip is required for this bundle"
    unzip -q "$BUNDLE" -d "$workdir/outer"
    archive="$(find "$workdir/outer" -type f -name '*.tar' -print -quit)"
    [[ -n "$archive" ]] || fail "inner vendor TAR was not found"
    mkdir -p "$workdir/package"
    tar -xf "$archive" -C "$workdir/package"
    ;;
  *.tar)
    mkdir -p "$workdir/package"
    tar -xf "$BUNDLE" -C "$workdir/package"
    ;;
  *) fail "expected the reviewed ZIP or its inner TAR archive" ;;
esac

header="$(find "$workdir/package" -type f -path '*/linux/include/wdt_dio.h' -print -quit)"
[[ -n "$header" ]] || fail "WDT_DIO package layout was not recognised"
package_root="$(dirname "$(dirname "$(dirname "$header")")")"
driver_dir="$package_root/linux/driver"
kernel_major="${kernel%%.*}"
library_source="$package_root/linux/deploy/lib${kernel_major}.x/libwdt_dio.so"
[[ -f "$driver_dir/wdt_dio.c" && -f "$driver_dir/wdt_sys.h" ]] || fail "vendor driver source is incomplete"
[[ -f "$library_source" ]] || fail "vendor library for kernel major $kernel_major is unavailable"

product="$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)"
if [[ "$product" != *"POC-451VTC"* ]]; then
  fail "this reviewed installation path is restricted to POC-451VTC; detected: ${product:-unknown}"
fi

log "Building wdt_dio.ko for $kernel"
make -C "$kernel_build" M="$driver_dir" clean >/dev/null
make -C "$kernel_build" M="$driver_dir" modules

module_target="/lib/modules/$kernel/extra/va-watchdog/wdt_dio.ko"
install -D -m 0644 "$driver_dir/wdt_dio.ko" "$module_target"
install -D -m 0644 "$library_source" "$LIBRARY_PATH"
install -D -m 0644 "$driver_dir/wdt_dio.c" "/usr/src/neousys-wdt-dio-$VERSION/wdt_dio.c"
install -D -m 0644 "$driver_dir/wdt_sys.h" "/usr/src/neousys-wdt-dio-$VERSION/wdt_sys.h"
printf '%s\n' 'wdt_dio' > /etc/modules-load.d/va-watchdog-neousys.conf
cat > /etc/udev/rules.d/60-va-watchdog-neousys.rules <<'EOF'
KERNEL=="wdt_dio", OWNER="root", GROUP="root", MODE="0600"
EOF

depmod -a "$kernel"
modprobe wdt_dio
udevadm control --reload-rules
udevadm trigger --name-match=wdt_dio || true
udevadm settle
[[ -c /dev/wdt_dio ]] || fail "wdt_dio loaded but /dev/wdt_dio was not created"

python3 - "$LIBRARY_PATH" <<'PY'
import ctypes
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
library = ctypes.CDLL(str(path))
missing = [name for name in ("InitWDT", "SetWDT", "StartWDT", "ResetWDT", "StopWDT") if not hasattr(library, name)]
if missing:
    raise SystemExit("vendor library is missing API symbols: " + ", ".join(missing))
print("Vendor library and API symbols verified; watchdog was not started by this probe.")
PY

log "Installed the Neousys driver and library without starting its watchdog"
log "Device: /dev/wdt_dio"
log "Module: $module_target"
log "Library: $LIBRARY_PATH"

if [[ "$ACTIVATE" != 1 ]]; then
  log "VA-Connect configuration was not changed. Re-run with --activate only during an attended test window."
  exit 0
fi

[[ -f "$CONFIG_PATH" ]] || fail "VA-Connect configuration not found: $CONFIG_PATH"
backup="$CONFIG_PATH.$(date -u +%Y%m%dT%H%M%SZ).neousys.bak"
cp -a "$CONFIG_PATH" "$backup"
systemctl stop va-watchdog-feed.service || true

log "Removing competing legacy and Intel watchdog paths"
for unit in watchdog.service wd_keepalive.service; do
  systemctl stop "$unit" 2>/dev/null || true
  systemctl disable "$unit" 2>/dev/null || true
  systemctl mask "$unit" 2>/dev/null || true
done
if command -v apt-get >/dev/null 2>&1 && dpkg-query -W -f='${Status}' watchdog 2>/dev/null | grep -q 'install ok installed'; then
  DEBIAN_FRONTEND=noninteractive apt-get remove -y watchdog
fi
rm -f /etc/modules-load.d/iTCO_wdt.conf /etc/modprobe.d/va-watchdog-itco.conf
cat > /etc/modprobe.d/va-watchdog-neousys-only.conf <<'EOF'
# This attended test build uses the Neousys WDT_DIO backend exclusively.
blacklist iTCO_wdt
blacklist iTCO_vendor_support
EOF
modprobe -r iTCO_wdt iTCO_vendor_support 2>/dev/null || true

PYTHONPATH="/opt/va-connect-watchdog-v3/v3" python3 - "$CONFIG_PATH" <<'PY'
import json
import os
import pathlib
import sys

from va_watchdog.watchdog_grace import delay_current_boot

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
hardware = payload.setdefault("hardware_watchdog", {})
hardware.update({
    "enabled": True,
    "backend": "neousys_wdt_dio",
    "device": "/dev/wdt_dio",
    "library_path": "/usr/local/lib/va-watchdog/vendor/libwdt_dio.so",
    "feed_interval_seconds": 10,
    "timeout_seconds": 30,
    "stale_heartbeat_seconds": 15,
    "magic_close": False,
})
temporary = path.with_suffix(path.suffix + ".neousys.tmp")
temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
os.chmod(temporary, 0o640)
os.replace(temporary, path)
delay_current_boot(payload, delay_seconds=900, extend=False)
PY

systemctl restart va-watchdog.service
systemctl restart va-watchdog-feed.service
sleep 2
systemctl is-active --quiet va-watchdog.service || fail "va-watchdog.service did not restart"
systemctl is-active --quiet va-watchdog-feed.service || fail "va-watchdog-feed.service did not restart"
log "Neousys feeding activated with a 15-minute attended safety window"
log "Configuration backup: $backup"
