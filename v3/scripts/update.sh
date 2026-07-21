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

systemctl restart va-watchdog
log "service restart requested"
sleep 2
systemctl is-active --quiet va-watchdog

write_state "completed" "update completed" "$commit_after"
log "update completed commit=$commit_after"
