#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="${VA_WATCHDOG_INSTALL_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}/v3"
REPO_DIR="$(cd "$ROOT_DIR/.." && pwd)"
VENV_DIR="$REPO_DIR/.venv"
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
  python3 - "$STATE_FILE" "$state" "$message" "$BRANCH" "$commit" "$ROOT_DIR/build.json" <<'PY'
import json
import os
import pathlib
import sys
from datetime import datetime, timezone

path = pathlib.Path(sys.argv[1])
state = sys.argv[2]
message = sys.argv[3]
branch = sys.argv[4]
commit = sys.argv[5]
build_file = pathlib.Path(sys.argv[6])
try:
    previous = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(previous, dict):
        previous = {}
except (OSError, ValueError):
    previous = {}
try:
    build = str(json.loads(build_file.read_text(encoding="utf-8")).get("build_number") or "")
except (OSError, ValueError, AttributeError):
    build = ""
now = datetime.now(timezone.utc).isoformat()
last_at = previous.get("last_completed_at") or (previous.get("updated_at") if previous.get("state") == "completed" else "")
last_build = previous.get("last_completed_build") or (build if previous.get("state") == "completed" else "")
last_commit = previous.get("last_completed_commit") or (previous.get("commit") if previous.get("state") == "completed" else "")
if state == "completed":
    last_at, last_build, last_commit = now, build, commit
payload = {
    "state": state,
    "message": message,
    "branch": branch,
    "commit": commit,
    "updated_at": now,
    "last_completed_at": last_at or "",
    "last_completed_build": last_build or "",
    "last_completed_commit": last_commit or "",
}
path.parent.mkdir(parents=True, exist_ok=True)
temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
os.replace(temporary, path)
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

# Parse the complete fetch/handoff function before Git can replace this file.
# No installation code from the old checkout may run after the pull.
main() {
  local commit_before commit_after
  commit_before="$("${GIT[@]}" rev-parse --short HEAD)"
  write_state "running" "update started" "$commit_before"
  log "update started branch=$BRANCH remote=$REMOTE commit=$commit_before"
  "${GIT[@]}" fetch "$REMOTE" "$BRANCH"
  "${GIT[@]}" pull --ff-only "$REMOTE" "$BRANCH"
  commit_after="$("${GIT[@]}" rev-parse --short HEAD)"
  log "update pulled commit=$commit_after; handing over to downloaded setup"
  if [[ ! -f "$ROOT_DIR/scripts/update_apply.sh" ]]; then
    log "Downloaded branch has no update_apply.sh; no services were changed"
    return 1
  fi
  /bin/bash "$ROOT_DIR/scripts/update_apply.sh" "$REMOTE" "$BRANCH"
}
main
