#!/usr/bin/env bash

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/va-connect.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

APP_NAME="${APP_NAME:-VA-Connect}"
APP_MATCH="${APP_MATCH:-va-connect}"
APP_START_CMD="${APP_START_CMD:-}"
APP_WORKDIR="${APP_WORKDIR:-/opt/va-connect}"
WATCHDOG_LOG="${WATCHDOG_LOG:-/var/log/va-connect-watchdog.log}"
STATE_DIR="${STATE_DIR:-/var/lib/va-connect-watchdog}"
COOLDOWN_FILE="${COOLDOWN_FILE:-$STATE_DIR/last_start_epoch}"
START_COOLDOWN_SECONDS="${START_COOLDOWN_SECONDS:-30}"
STARTUP_GRACE_SECONDS="${STARTUP_GRACE_SECONDS:-15}"

timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

log_line() {
  local level="$1"
  local message="$2"
  mkdir -p "$(dirname "$WATCHDOG_LOG")" "$STATE_DIR"
  printf '%s [%s] %s\n' "$(timestamp)" "$level" "$message" >> "$WATCHDOG_LOG"
}

is_running() {
  pgrep -f -- "$APP_MATCH" >/dev/null 2>&1
}

seconds_since_last_start() {
  if [[ ! -f "$COOLDOWN_FILE" ]]; then
    echo 999999
    return
  fi

  local last_start
  last_start="$(cat "$COOLDOWN_FILE" 2>/dev/null || echo 0)"
  local now
  now="$(date +%s)"
  echo $((now - last_start))
}

record_start_attempt() {
  mkdir -p "$STATE_DIR"
  date +%s > "$COOLDOWN_FILE"
}

start_app() {
  if [[ -z "$APP_START_CMD" ]]; then
    log_line "ERROR" "APP_START_CMD is empty; cannot start $APP_NAME."
    return 1
  fi

  if [[ ! -d "$APP_WORKDIR" ]]; then
    log_line "ERROR" "APP_WORKDIR does not exist: $APP_WORKDIR"
    return 1
  fi

  log_line "WARN" "$APP_NAME not running. Starting with command: $APP_START_CMD"
  record_start_attempt

  (
    cd "$APP_WORKDIR" || exit 1
    nohup bash -lc "$APP_START_CMD" >> "$WATCHDOG_LOG" 2>&1 &
  )
}

main() {
  if is_running; then
    log_line "OK" "$APP_NAME is running."
    exit 0
  fi

  local elapsed
  elapsed="$(seconds_since_last_start)"
  if (( elapsed < START_COOLDOWN_SECONDS )); then
    log_line "WARN" "$APP_NAME is down, but last start attempt was ${elapsed}s ago. Cooldown active."
    exit 1
  fi

  if ! start_app; then
    exit 2
  fi

  sleep "$STARTUP_GRACE_SECONDS"

  if is_running; then
    log_line "OK" "$APP_NAME started successfully."
    exit 0
  fi

  log_line "ERROR" "$APP_NAME still not detected after start attempt."
  exit 3
}

main "$@"
