#!/usr/bin/env bash
set -e
sudo systemctl stop va-watchdog.service || true
sudo systemctl disable va-watchdog.service || true
sudo rm -f /etc/systemd/system/va-watchdog.service
sudo systemctl daemon-reload
echo "Uninstalled VA-Connect Watchdog V3 service"
