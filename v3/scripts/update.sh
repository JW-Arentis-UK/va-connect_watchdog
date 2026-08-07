#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="$(cd "$ROOT_DIR/.." && pwd)"
STATE_DIR="${VA_WATCHDOG_STATE_DIR:-/var/lib/va-watchdog}"
STATE_FILE="${VA_WATCHDOG_STATE_FILE:-$STATE_DIR/update-state.json}"
LOG_FILE="${VA_WATCHDOG_LOG_FILE:-$STATE_DIR/update.log}"
REMOTE="${1:-origin}"
GIT=(git -c "safe.directory=$REPO_DIR" -C "$REPO_DIR")
BRANCH="${2:-$("${GIT[@]}" rev-parse --abbrev-ref HEAD)}"

mkdir -p "$(dirname "$STATE_FILE")" "$(dirname "$LOG_FILE")"

write_state() {
  local state="$1"
  local message="$2"
  local commit="${3:-}"
  python3 - "$STATE_FILE" "$state" "$message" "$BRANCH" "$commit" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
state = sys.argv[2]
message = sys.argv[3]
branch = sys.argv[4]
commit = sys.argv[5]
payload = {
    "state": state,
    "message": message,
    "branch": branch,
    "commit": commit,
    "updated_at": datetime.now(timezone.utc).isoformat(),
}
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
}

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG_FILE"
}

update_failed() {
  local exit_code=$?
  local line_number="${1:-unknown}"
  local message="update failed at line $line_number (exit $exit_code)"
  write_state "failed" "$message"
  log "$message"
  exit "$exit_code"
}
trap 'update_failed "$LINENO"' ERR

commit_before="$("${GIT[@]}" rev-parse --short HEAD)"
write_state "running" "update started" "$commit_before"
log "update started branch=$BRANCH remote=$REMOTE commit=$commit_before"

"${GIT[@]}" fetch "$REMOTE" "$BRANCH"
"${GIT[@]}" pull --ff-only "$REMOTE" "$BRANCH"
commit_after="$("${GIT[@]}" rev-parse --short HEAD)"
log "update pulled commit=$commit_after"

if [ -f "$ROOT_DIR/vendor/neousys/WDT_DIO_202505_v2-4-1-0_Linux.zip" ]; then
  log "installing bundled Neousys WDT_DIO driver without activating hardware feeding"
  if ! command -v gcc >/dev/null 2>&1 || [ ! -d "/lib/modules/$(uname -r)/build" ]; then
    apt-get update
    apt-get install -y build-essential "linux-headers-$(uname -r)" unzip
  fi
  /bin/bash "$ROOT_DIR/scripts/install_neousys_wdt.sh"
  log "Neousys WDT_DIO driver installed"
fi

if [ -f "$ROOT_DIR/systemd/va-watchdog.service" ]; then
  install -m 0644 "$ROOT_DIR/systemd/va-watchdog.service" /etc/systemd/system/va-watchdog.service
  log "installed current va-watchdog systemd unit"
fi
if [ -f "$ROOT_DIR/systemd/va-watchdog-feed.service" ]; then
  install -m 0644 "$ROOT_DIR/systemd/va-watchdog-feed.service" /etc/systemd/system/va-watchdog-feed.service
  log "installed current va-watchdog-feed systemd unit"
fi
systemctl daemon-reload

systemctl restart va-watchdog-feed
log "hardware feeder restart requested"
systemctl restart va-watchdog
log "main service restart requested"
sleep 2
systemctl is-active --quiet va-watchdog-feed
systemctl is-active --quiet va-watchdog

write_state "completed" "update completed" "$commit_after"
log "update completed commit=$commit_after"
