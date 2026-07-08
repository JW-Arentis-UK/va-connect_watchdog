#!/usr/bin/env bash
set +e

echo "===== Kernel ====="
uname -a
echo

echo "===== Hardware ====="
lscpu | grep "Model name"
echo

echo "===== Modules ====="
lsmod | grep -Ei "itco|watchdog|wdat"
echo

echo "===== Devices ====="
ls -l /dev/watchdog*
echo

echo "===== Module info ====="
modinfo iTCO_wdt 2>/dev/null
echo

echo "===== Load module ====="
sudo modprobe iTCO_wdt
echo "Exit code: $?"
echo

echo "===== Devices after modprobe ====="
ls -l /dev/watchdog*
echo

echo "===== wdctl ====="
sudo wdctl /dev/watchdog0
echo

echo "===== dmesg ====="
sudo dmesg | grep -Ei "itco|watchdog|tco" | tail -50
echo

echo "===== systemd watchdog ====="
systemctl show va-watchdog -p Type -p WatchdogUSec -p WatchdogTimestamp
echo

echo "===== watchdog daemon ====="
systemctl status watchdog --no-pager
echo

echo "===== Module autoload ====="
cat /etc/modules-load.d/iTCO_wdt.conf 2>/dev/null
echo

echo "===== BIOS devices ====="
find /sys -name watchdog -type d 2>/dev/null
