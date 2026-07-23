#!/usr/bin/env bash
set -uo pipefail

DURATION_SECONDS="${1:-900}"
INTERVAL_SECONDS="${2:-5}"
OUTPUT_ROOT="${3:-/tmp}"
IDENTITY_SLUG="${4:-}"
SITE_NAME="${5:-}"
ASSET_ID="${6:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HOST="$(hostname 2>/dev/null || echo unknown)"
if [[ -n "$IDENTITY_SLUG" ]]; then
  OUT="${OUTPUT_ROOT%/}/va-watchdog-stage0-${IDENTITY_SLUG}-${HOST}-${STAMP}"
else
  OUT="${OUTPUT_ROOT%/}/va-watchdog-stage0-${HOST}-${STAMP}"
fi
SAMPLES="$OUT/samples.tsv"

case "$DURATION_SECONDS:$INTERVAL_SECONDS" in
  *[!0-9:]*|:*|*:0) echo "Duration and interval must be positive whole seconds." >&2; exit 2 ;;
esac
if (( DURATION_SECONDS <= 0 || INTERVAL_SECONDS <= 0 )); then
  echo "Duration and interval must be positive whole seconds." >&2
  exit 2
fi

mkdir -p "$OUT"

run_capture() {
  local name="$1"
  shift
  {
    echo "# command: $*"
    timeout 15 "$@"
  } >"$OUT/$name.txt" 2>&1 || true
}

read_one_line() {
  local path="$1"
  if [[ -r "$path" ]]; then
    tr '\t\r\n' '   ' <"$path"
  fi
}

proc_sample() {
  local pid="$1"
  if [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/stat" ]]; then
    ps -p "$pid" -o pid=,pcpu=,rss=,nlwp=,etimes= 2>/dev/null | awk '{$1=$1; print}' | tr '\t\r\n' '   '
  fi
}

proc_io_sample() {
  local pid="$1"
  if [[ -n "$pid" && "$pid" != "0" && -r "/proc/$pid/io" ]]; then
    awk '/^(rchar|wchar|read_bytes|write_bytes|cancelled_write_bytes):/ {printf "%s=%s,", $1, $2}' "/proc/$pid/io" 2>/dev/null
  fi
}

cgroup_io_sample() {
  local unit="$1"
  local control_group
  control_group="$(systemctl show "$unit" -p ControlGroup --value 2>/dev/null || true)"
  if [[ -n "$control_group" && -r "/sys/fs/cgroup$control_group/io.stat" ]]; then
    tr '\t\r\n' '   ' <"/sys/fs/cgroup$control_group/io.stat"
  fi
}

unit_systemd_sample() {
  systemctl show "$1" -p CPUUsageNSec -p MemoryCurrent -p TasksCurrent 2>/dev/null | tr '\t\r\n' '   '
}

diskstats_sample() {
  awk '$3 ~ /^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+)$/ {$1=$1; printf "%s;", $0}' /proc/diskstats 2>/dev/null
}

vmstat_sample() {
  awk '/^(pgpgin|pgpgout|pswpin|pswpout|nr_dirty|nr_writeback|nr_dirtied|nr_written) / {printf "%s=%s,", $1, $2}' /proc/vmstat 2>/dev/null
}

unit_pid() {
  systemctl show "$1" -p MainPID --value 2>/dev/null || true
}

data_bytes() {
  du -sb /var/lib/va-watchdog 2>/dev/null | awk '{print $1}' || echo 0
}

{
  echo "VA-Connect Watchdog Stage 0 baseline"
  echo "started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host=$HOST"
  echo "site_name=$SITE_NAME"
  echo "asset_id=$ASSET_ID"
  echo "duration_seconds=$DURATION_SECONDS"
  echo "interval_seconds=$INTERVAL_SECONDS"
  echo "user=$(id 2>/dev/null || true)"
} >"$OUT/manifest.txt"

run_capture uname uname -a
run_capture os-release cat /etc/os-release
run_capture lscpu lscpu
run_capture memory-free free -m
run_capture disks lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,MODEL,SERIAL
run_capture mounts findmnt
run_capture filesystem df -hT
run_capture boot-id cat /proc/sys/kernel/random/boot_id
run_capture uptime cat /proc/uptime
run_capture start-diskstats cat /proc/diskstats
run_capture start-vmstat cat /proc/vmstat
run_capture git-state git -C /opt/va-connect-watchdog-v3 status --short --branch
run_capture git-commit git -C /opt/va-connect-watchdog-v3 log -1 --format=fuller
run_capture main-unit systemctl cat va-watchdog.service
run_capture feed-unit systemctl cat va-watchdog-feed.service
run_capture main-status systemctl status va-watchdog.service --no-pager -l
run_capture feed-status systemctl status va-watchdog-feed.service --no-pager -l
run_capture main-enabled systemctl is-enabled va-watchdog.service
run_capture feed-enabled systemctl is-enabled va-watchdog-feed.service
run_capture main-properties systemctl show va-watchdog.service -p ActiveState -p SubState -p MainPID -p NRestarts -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent -p WatchdogUSec -p WatchdogTimestampMonotonic
run_capture feed-properties systemctl show va-watchdog-feed.service -p ActiveState -p SubState -p MainPID -p NRestarts -p CPUUsageNSec -p MemoryCurrent -p MemoryPeak -p TasksCurrent
run_capture journal-disk-usage journalctl --disk-usage
run_capture journald-config systemd-analyze cat-config systemd/journald.conf
if [[ -d /var/log/journal ]]; then
  echo "persistent_journal_directory=yes" >>"$OUT/manifest.txt"
else
  echo "persistent_journal_directory=no" >>"$OUT/manifest.txt"
fi
run_capture config-stat stat /etc/va-watchdog/config.json
run_capture data-files find /var/lib/va-watchdog -maxdepth 2 -type f -printf '%s\t%TY-%Tm-%TdT%TH:%TM:%TS\t%p\n'
run_capture healthz wget -qO- http://127.0.0.1:9110/api/healthz
run_capture version wget -qO- http://127.0.0.1:9110/api/version

if [[ -r /etc/va-watchdog/config.json ]] && command -v python3 >/dev/null 2>&1; then
  python3 - /etc/va-watchdog/config.json "$OUT/config-redacted.json" <<'PY' 2>/dev/null || true
import json
import sys

source, destination = sys.argv[1:3]
sensitive = {"password", "passphrase", "token", "secret", "api_key", "private_key"}


def redact(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in sensitive else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


with open(source, "r", encoding="utf-8") as handle:
    payload = json.load(handle)
with open(destination, "w", encoding="utf-8") as handle:
    json.dump(redact(payload), handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
fi

for path in heartbeat-state.json hardware-watchdog-feed.json status.json; do
  if [[ -r "/var/lib/va-watchdog/$path" ]]; then
    cp "/var/lib/va-watchdog/$path" "$OUT/start-$path" 2>/dev/null || true
  fi
done

START_DATA_BYTES="$(data_bytes)"
echo "start_data_bytes=$START_DATA_BYTES" >>"$OUT/manifest.txt"

printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  utc epoch uptime loadavg proc_stat mem_available_kb psi_cpu psi_memory psi_io diskstats vmstat main_process feed_process main_systemd feed_systemd main_process_io feed_process_io main_cgroup_io feed_cgroup_io >"$SAMPLES"

START_EPOCH="$(date +%s)"
END_EPOCH=$((START_EPOCH + DURATION_SECONDS))
NEXT_EPOCH="$START_EPOCH"

while [[ "$(date +%s)" -lt "$END_EPOCH" ]]; do
  NOW_EPOCH="$(date +%s)"
  MAIN_PID="$(unit_pid va-watchdog.service)"
  FEED_PID="$(unit_pid va-watchdog-feed.service)"
  MAIN_SYSTEMD="$(unit_systemd_sample va-watchdog.service)"
  FEED_SYSTEMD="$(unit_systemd_sample va-watchdog-feed.service)"
  MEM_AVAILABLE="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" \
    "$NOW_EPOCH" \
    "$(awk '{print $1}' /proc/uptime 2>/dev/null)" \
    "$(read_one_line /proc/loadavg)" \
    "$(head -n 5 /proc/stat 2>/dev/null | tr '\t\r\n' '   ')" \
    "$MEM_AVAILABLE" \
    "$(read_one_line /proc/pressure/cpu)" \
    "$(read_one_line /proc/pressure/memory)" \
    "$(read_one_line /proc/pressure/io)" \
    "$(diskstats_sample)" \
    "$(vmstat_sample)" \
    "$(proc_sample "$MAIN_PID")" \
    "$(proc_sample "$FEED_PID")" \
    "$MAIN_SYSTEMD" \
    "$FEED_SYSTEMD" \
    "$(proc_io_sample "$MAIN_PID")" \
    "$(proc_io_sample "$FEED_PID")" \
    "$(cgroup_io_sample va-watchdog.service)" \
    "$(cgroup_io_sample va-watchdog-feed.service)" >>"$SAMPLES"

  NEXT_EPOCH=$((NEXT_EPOCH + INTERVAL_SECONDS))
  SLEEP_SECONDS=$((NEXT_EPOCH - $(date +%s)))
  if (( SLEEP_SECONDS > 0 )); then
    sleep "$SLEEP_SECONDS"
  fi
done

END_DATA_BYTES="$(data_bytes)"
{
  echo "finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "end_data_bytes=$END_DATA_BYTES"
  echo "data_growth_bytes=$((END_DATA_BYTES - START_DATA_BYTES))"
} >>"$OUT/manifest.txt"

for path in heartbeat-state.json hardware-watchdog-feed.json status.json; do
  if [[ -r "/var/lib/va-watchdog/$path" ]]; then
    cp "/var/lib/va-watchdog/$path" "$OUT/end-$path" 2>/dev/null || true
  fi
done

tail -n 2000 /var/lib/va-watchdog/heartbeat.jsonl >"$OUT/heartbeat-tail.jsonl" 2>/dev/null || true
tail -n 500 /var/lib/va-watchdog/events.jsonl >"$OUT/events-tail.jsonl" 2>/dev/null || true
run_capture main-journal journalctl -u va-watchdog.service --since "@$START_EPOCH" --no-pager
run_capture feed-journal journalctl -u va-watchdog-feed.service --since "@$START_EPOCH" --no-pager
run_capture kernel-journal journalctl -k --since "@$START_EPOCH" --no-pager
run_capture warning-journal journalctl -p warning --since "@$START_EPOCH" --no-pager
run_capture end-diskstats cat /proc/diskstats
run_capture end-vmstat cat /proc/vmstat
run_capture final-data-files find /var/lib/va-watchdog -maxdepth 2 -type f -printf '%s\t%TY-%Tm-%TdT%TH:%TM:%TS\t%p\n'

ARCHIVE="$OUT.tar.gz"
if tar -C "$(dirname "$OUT")" -czf "$ARCHIVE" "$(basename "$OUT")"; then
  ROOT_REAL="$(readlink -f "$OUTPUT_ROOT")"
  OUT_REAL="$(readlink -f "$OUT")"
  case "$OUT_REAL" in
    "$ROOT_REAL"/va-watchdog-stage0-*) rm -rf -- "$OUT_REAL" ;;
  esac
  echo "Baseline complete: $ARCHIVE"
else
  echo "Baseline archive failed; uncompressed evidence retained at $OUT" >&2
  exit 1
fi
