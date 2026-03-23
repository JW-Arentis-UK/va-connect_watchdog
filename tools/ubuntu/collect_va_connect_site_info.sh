#!/usr/bin/env bash

set -euo pipefail

OUTPUT_DIR="${OUTPUT_DIR:-$HOME/Desktop}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
HOSTNAME_SHORT="$(hostname)"
OUTPUT_FILE="$OUTPUT_DIR/va_connect_site_info_${HOSTNAME_SHORT}_${TIMESTAMP}.txt"

mkdir -p "$OUTPUT_DIR"

section() {
  local title="$1"
  printf '\n===== %s =====\n' "$title" >> "$OUTPUT_FILE"
}

run_cmd() {
  local label="$1"
  shift
  section "$label"
  {
    printf '$ %s\n' "$*"
    "$@"
  } >> "$OUTPUT_FILE" 2>&1 || true
}

run_shell() {
  local label="$1"
  local command="$2"
  section "$label"
  {
    printf '$ %s\n' "$command"
    bash -lc "$command"
  } >> "$OUTPUT_FILE" 2>&1 || true
}

{
  printf 'VA-Connect encoder site info capture\n'
  printf 'Created: %s\n' "$(date -Is)"
  printf 'Output file: %s\n' "$OUTPUT_FILE"
} > "$OUTPUT_FILE"

run_cmd "User" whoami
run_cmd "Hostname" hostname
run_cmd "Working Directory" pwd
run_cmd "Home Listing" ls -la "$HOME"
run_cmd "Desktop Listing" ls -la "$HOME/Desktop"

run_shell "Desktop Launchers" "ls -la \"$HOME\"/Desktop/*.desktop"
run_shell "Desktop Shell Scripts" "ls -la \"$HOME\"/Desktop/*.sh"

run_shell "VA-Connect Processes" "ps -ef | grep -i va-connect | grep -v grep"
run_shell "TeamViewer Processes" "ps -ef | grep -i teamviewer | grep -v grep"
run_shell "All Desktop Processes" "ps -ef | grep -E 'desktop|x11|wayland' | grep -v grep"

run_cmd "IP Address" ip addr
run_cmd "IP Route" ip route
run_shell "Default Route Lookup" "ip route get 1.1.1.1"

run_shell "Systemd Services Matching VA" "systemctl list-units --type=service --all | grep -i 'va\\|connect'"
run_shell "Systemd Services Matching TeamViewer" "systemctl list-units --type=service --all | grep -i teamviewer"
run_shell "Systemd Unit Files Matching VA" "systemctl list-unit-files | grep -i 'va\\|connect'"

run_shell "Recent Journal Matching VA" "journalctl -n 120 --no-pager | grep -i 'va\\|connect'"
run_shell "Recent Journal Matching TeamViewer" "journalctl -n 120 --no-pager | grep -i teamviewer"

run_shell "NetworkManager Status" "systemctl status NetworkManager --no-pager"
run_shell "systemd-networkd Status" "systemctl status systemd-networkd --no-pager"

section "Done"
printf 'Saved to %s\n' "$OUTPUT_FILE" >> "$OUTPUT_FILE"

printf 'Site info saved to:\n%s\n' "$OUTPUT_FILE"
