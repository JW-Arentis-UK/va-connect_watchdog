#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."
sudo python3 -m va_watchdog.watchdog
