#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[va-watchdog-verify]"
FAILURES=0

log() {
  printf '%s %s\n' "$LOG_PREFIX" "$*"
}

pass() {
  log "PASS: $*"
}

warn() {
  log "WARN: $*"
}

fail() {
  log "FAIL: $*"
  FAILURES=$((FAILURES + 1))
}

section() {
  printf '\n%s %s\n' "$LOG_PREFIX" "=== $* ==="
}

check_command() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    pass "command available: $name"
  else
    fail "missing command: $name"
  fi
}

check_path() {
  local path="$1"
  if [[ -e "$path" ]]; then
    pass "path exists: $path"
  else
    warn "path missing: $path"
  fi
}

check_systemd_unit() {
  local unit="$1"
  if systemctl list-unit-files "$unit" >/dev/null 2>&1; then
    local active enabled
    active="$(systemctl is-active "$unit" 2>/dev/null || true)"
    enabled="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    log "$unit: active=$active enabled=$enabled"
    if [[ "$active" == "active" ]]; then
      pass "unit active: $unit"
    else
      fail "unit not active: $unit"
    fi
  else
    warn "unit not installed: $unit"
  fi
}

check_systemd_status() {
  local unit="$1"
  if systemctl status "$unit" --no-pager --full >/dev/null 2>&1; then
    pass "status readable: $unit"
  else
    warn "status unavailable or unit inactive: $unit"
  fi
}

check_git_checkout() {
  local repo="$1"
  if [[ ! -d "$repo/.git" ]]; then
    warn "not a git checkout: $repo"
    return
  fi

  local branch commit status
  branch="$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  commit="$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  if git -C "$repo" diff --quiet --ignore-submodules HEAD >/dev/null 2>&1; then
    status="clean"
  else
    status="dirty"
  fi
  log "git: $repo branch=$branch commit=$commit status=$status"
  pass "git checkout readable: $repo"
}

check_http() {
  local url="$1"
  local label="$2"
  if curl -fsS --max-time 8 "$url" >/dev/null; then
    pass "http ok: $label ($url)"
  else
    fail "http failed: $label ($url)"
  fi
}

check_json_field() {
  local file="$1"
  local jq_expr="$2"
  local label="$3"
  if [[ ! -f "$file" ]]; then
    warn "json missing: $file"
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    local value
    value="$(python3 - "$file" "$jq_expr" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
expr = sys.argv[2]
payload = json.loads(path.read_text(encoding="utf-8"))
value = payload
for part in expr.split("."):
    if not part:
        continue
    if isinstance(value, dict):
        value = value.get(part)
    else:
        value = None
        break
print("" if value is None else value)
PY
)"
    log "$label: $value"
    if [[ -n "$value" ]]; then
      pass "$label present"
    else
      warn "$label empty"
    fi
  else
    warn "python3 unavailable for json inspection: $file"
  fi
}

check_log_tail() {
  local file="$1"
  local lines="${2:-20}"
  if [[ -f "$file" ]]; then
    log "tail: $file"
    tail -n "$lines" "$file" || true
  else
    warn "log missing: $file"
  fi
}

section "Commands"
check_command systemctl
check_command curl
check_command git
check_command python3

section "Installed Paths"
check_path /opt/va-connect-watchdog
check_path /opt/va-connect-watchdog/build-info.json
check_path /opt/va-connect-watchdog/site-watchdog.json
check_path /opt/va-connect-watchdog-v3
check_path /etc/va-watchdog/config.json
check_path /var/lib/va-watchdog
check_path /var/lib/va-connect-site-watchdog

section "Git Checkouts"
check_git_checkout /opt/va-connect-watchdog
check_git_checkout /opt/va-connect-watchdog-v3
check_git_checkout /home/vsuser/Desktop/va-connect-watchdog

section "Services"
check_systemd_unit va-connect-site-watchdog.service
check_systemd_unit va-connect-watchdog-web.service
check_systemd_unit va-watchdog.service
check_systemd_unit va-watchdog-feed.service
check_systemd_unit va-connect-watchdog.timer

section "Service Status"
check_systemd_status va-connect-site-watchdog.service
check_systemd_status va-connect-watchdog-web.service
check_systemd_status va-watchdog.service
check_systemd_status va-watchdog-feed.service
check_systemd_status va-connect-watchdog.timer

section "Web/API"
check_http http://127.0.0.1/api/status "v2 web status"
check_http http://127.0.0.1:9110/api/status "v3 status api"
check_http http://127.0.0.1:9110/api/healthz "v3 health endpoint"

section "Build Info"
check_json_field /opt/va-connect-watchdog/build-info.json build_number "v2 build number"
check_json_field /opt/va-connect-watchdog/build-info.json git_commit "v2 git commit"
check_json_field /opt/va-connect-watchdog-v3/build-info.json git_commit "v3 git commit"
check_json_field /opt/va-connect-watchdog-v3/build-info.json deployed_at "v3 deployed at"

section "Logs"
check_log_tail /var/log/va-connect-site-watchdog/web-update.log 20
check_log_tail /var/log/va-connect-site-watchdog/web-export.log 20
check_log_tail /var/log/va-watchdog.log 20
check_log_tail /opt/va-connect-watchdog/logs/v2.log 20

section "Summary"
if [[ "$FAILURES" -eq 0 ]]; then
  pass "all checks passed"
  exit 0
fi

fail "$FAILURES check(s) failed"
exit 1
