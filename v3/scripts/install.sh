#!/usr/bin/env bash
set -e

INSTALL_DIR="/opt/va-connect-watchdog-v3"
CONFIG_DIR="/etc/va-watchdog"
DATA_DIR="/var/lib/va-watchdog"
APP_DIR="$INSTALL_DIR/v3"

sudo mkdir -p "$CONFIG_DIR" "$DATA_DIR"

if [ ! -f "$CONFIG_DIR/config.json" ]; then
  sudo cp "$APP_DIR/config.example.json" "$CONFIG_DIR/config.json"
fi

sudo cp "$APP_DIR/systemd/va-watchdog.service" /etc/systemd/system/va-watchdog.service
sudo cp "$APP_DIR/systemd/va-watchdog-feed.service" /etc/systemd/system/va-watchdog-feed.service
sudo systemctl daemon-reload
sudo systemctl enable va-watchdog-feed.service
sudo systemctl enable va-watchdog.service
sudo systemctl restart va-watchdog-feed.service
sudo systemctl restart va-watchdog.service

echo "Installed VA-Connect Watchdog"
echo "Status: sudo systemctl status va-watchdog"
echo "Web: http://<gateway-ip>:9110/"
