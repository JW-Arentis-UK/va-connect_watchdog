#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/va-connect-watchdog-v3"
CONFIG_DIR="/etc/va-watchdog"
DATA_DIR="/var/lib/va-watchdog"

sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
  sudo cp "$INSTALL_DIR/config.example.json" "$CONFIG_DIR/config.json"
fi

sudo cp "$INSTALL_DIR/systemd/va-watchdog.service" /etc/systemd/system/va-watchdog.service
sudo systemctl daemon-reload
sudo systemctl enable va-watchdog.service
sudo systemctl restart va-watchdog.service

echo "Installed VA-Connect Watchdog V3"
echo "Status: sudo systemctl status va-watchdog"
echo "Web: http://<gateway-ip>:9110/"
