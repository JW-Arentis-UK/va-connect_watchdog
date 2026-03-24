#!/usr/bin/env bash

set -euo pipefail

EVENTS_PATH="${EVENTS_PATH:-/var/log/va-connect-site-watchdog/events.jsonl}"
METRICS_PATH="${METRICS_PATH:-/var/log/va-connect-site-watchdog/metrics.jsonl}"
STATE_PATH="${STATE_PATH:-/var/lib/va-connect-site-watchdog/state.json}"
BUILD_INFO_PATH="${BUILD_INFO_PATH:-/opt/va-connect-watchdog/build-info.json}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/var/log/va-connect-site-watchdog/snapshots}"
OUTPUT_ROOT="${OUTPUT_ROOT:-$HOME/Desktop}"

INCIDENT_TIME=""
REBOOT_TIME=""
SINCE_TIME=""
UNTIL_TIME=""
BEFORE_MINUTES=30
AFTER_MINUTES=30

usage() {
  cat <<'EOF'
Usage:
  ./export_watchdog_incident.sh --incident "2026-03-23 22:26"
  ./export_watchdog_incident.sh --incident "2026-03-23 22:26" --reboot "2026-03-24 08:12"
  ./export_watchdog_incident.sh --since "2026-03-23 21:56" --until "2026-03-24 08:42"

Options:
  --incident "YYYY-MM-DD HH:MM"
    The main fault time. Export starts BEFORE_MINUTES before this.

  --reboot "YYYY-MM-DD HH:MM"
    Optional reboot time. If supplied, export ends AFTER_MINUTES after this.

  --since "YYYY-MM-DD HH:MM"
  --until "YYYY-MM-DD HH:MM"
    Explicit window instead of incident/reboot mode.

  --before-minutes N
    Minutes before the incident time. Default: 30

  --after-minutes N
    Minutes after the incident time or reboot time. Default: 30

This creates a timestamped export folder on the Desktop and a .tar.gz archive beside it.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --incident)
      INCIDENT_TIME="${2:-}"
      shift 2
      ;;
    --reboot)
      REBOOT_TIME="${2:-}"
      shift 2
      ;;
    --since)
      SINCE_TIME="${2:-}"
      shift 2
      ;;
    --until)
      UNTIL_TIME="${2:-}"
      shift 2
      ;;
    --before-minutes)
      BEFORE_MINUTES="${2:-30}"
      shift 2
      ;;
    --after-minutes)
      AFTER_MINUTES="${2:-30}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SINCE_TIME" || -z "$UNTIL_TIME" ]]; then
  if [[ -z "$INCIDENT_TIME" ]]; then
    echo "Provide either --incident or both --since and --until."
    usage
    exit 1
  fi

  SINCE_TIME="$(date -d "$INCIDENT_TIME - ${BEFORE_MINUTES} minutes" '+%Y-%m-%d %H:%M:%S')"
  if [[ -n "$REBOOT_TIME" ]]; then
    UNTIL_TIME="$(date -d "$REBOOT_TIME + ${AFTER_MINUTES} minutes" '+%Y-%m-%d %H:%M:%S')"
  else
    UNTIL_TIME="$(date -d "$INCIDENT_TIME + ${AFTER_MINUTES} minutes" '+%Y-%m-%d %H:%M:%S')"
  fi
fi

STAMP="$(date '+%Y%m%d_%H%M%S')"
EXPORT_DIR="$OUTPUT_ROOT/watchdog_incident_export_$STAMP"
mkdir -p "$EXPORT_DIR"

cat > "$EXPORT_DIR/README.txt" <<EOF
VA-Connect watchdog incident export

Window start : $SINCE_TIME
Window end   : $UNTIL_TIME
Incident time: ${INCIDENT_TIME:-not supplied}
Reboot time  : ${REBOOT_TIME:-not supplied}

Included:
- Filtered watchdog events
- Filtered watchdog metrics
- Current watchdog state and build info
- System/kernel/service journals for the window
- Boot history
- Snapshot directory listing
- Snapshot folders captured within the window
EOF

cp "$STATE_PATH" "$EXPORT_DIR/state.json" 2>/dev/null || true
cp "$BUILD_INFO_PATH" "$EXPORT_DIR/build-info.json" 2>/dev/null || true

python3 - "$EVENTS_PATH" "$METRICS_PATH" "$EXPORT_DIR" "$SINCE_TIME" "$UNTIL_TIME" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

events_path = Path(sys.argv[1])
metrics_path = Path(sys.argv[2])
export_dir = Path(sys.argv[3])
since = datetime.fromisoformat(sys.argv[4].replace(" ", "T"))
until = datetime.fromisoformat(sys.argv[5].replace(" ", "T"))

def in_window(ts: str) -> bool:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        try:
            dt = datetime.fromisoformat(ts)
        except Exception:
            return False
    if dt.tzinfo is not None:
      dt = dt.astimezone().replace(tzinfo=None)
    return since <= dt <= until

def filter_jsonl(src: Path, dest: Path):
    items = []
    if src.exists():
        for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                item = json.loads(line)
            except Exception:
                continue
            ts = str(item.get("ts", ""))
            if in_window(ts):
                items.append(item)
    dest.write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in items), encoding="utf-8")

filter_jsonl(events_path, export_dir / "events_window.jsonl")
filter_jsonl(metrics_path, export_dir / "metrics_window.jsonl")
PY

journalctl --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_system_window.txt" 2>&1 || true
journalctl -k --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_kernel_window.txt" 2>&1 || true
journalctl -u esg.service --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_esg_window.txt" 2>&1 || true
journalctl -u bridge.service --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_bridge_window.txt" 2>&1 || true
journalctl -u sysops.service --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_sysops_window.txt" 2>&1 || true
journalctl -u teamviewerd.service --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_teamviewer_window.txt" 2>&1 || true
journalctl -u NetworkManager --since "$SINCE_TIME" --until "$UNTIL_TIME" --no-pager > "$EXPORT_DIR/journal_network_window.txt" 2>&1 || true
last -x -n 40 > "$EXPORT_DIR/last_reboots.txt" 2>&1 || true
journalctl --list-boots > "$EXPORT_DIR/boot_list.txt" 2>&1 || true

find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d | sort > "$EXPORT_DIR/snapshot_dirs.txt" 2>&1 || true

while IFS= read -r snapshot_path; do
  [[ -z "$snapshot_path" ]] && continue
  snapshot_name="$(basename "$snapshot_path")"
  cp -r "$snapshot_path" "$EXPORT_DIR/$snapshot_name" 2>/dev/null || true
done < <(
  find "$SNAPSHOT_DIR" -maxdepth 1 -mindepth 1 -type d -newermt "$SINCE_TIME" ! -newermt "$UNTIL_TIME" 2>/dev/null | sort
)

tar -czf "$EXPORT_DIR.tar.gz" -C "$OUTPUT_ROOT" "$(basename "$EXPORT_DIR")"

echo
echo "Incident export created:"
echo "  Folder: $EXPORT_DIR"
echo "  Archive: $EXPORT_DIR.tar.gz"
