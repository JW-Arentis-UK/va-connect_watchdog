#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="${VA_WATCHDOG_STATE_DIR:-/var/lib/va-watchdog}"
STATE_FILE="$STATE_DIR/update-state.json"
LOG_FILE="$STATE_DIR/update.log"
REMOTE="${1:-origin}"
BRANCH="${2:-$(git -C "$ROOT_DIR" rev-parse --abbrev-ref HEAD)}"

mkdir -p "$STATE_DIR"

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

trap 'write_state "failed" "update failed"; log "update failed"; exit 1' ERR

commit_before="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
write_state "running" "update started" "$commit_before"
log "update started branch=$BRANCH remote=$REMOTE commit=$commit_before"

git -C "$ROOT_DIR" fetch "$REMOTE" "$BRANCH"
git -C "$ROOT_DIR" pull --ff-only "$REMOTE" "$BRANCH"
commit_after="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
log "update pulled commit=$commit_after"

systemctl restart va-watchdog
log "service restart requested"

write_state "completed" "update completed" "$commit_after"
log "update completed commit=$commit_after"
