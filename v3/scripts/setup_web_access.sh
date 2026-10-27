#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="${VA_WATCHDOG_CONFIG_DIR:-/etc/va-watchdog}"
DATA_DIR="${VA_WATCHDOG_DATA_DIR:-/var/lib/va-watchdog}"
[[ "$EUID" -eq 0 ]] || { echo 'Run web access setup as root' >&2; exit 1; }
getent group va-watchdog-web >/dev/null || groupadd --system va-watchdog-web
id va-watchdog-web >/dev/null 2>&1 || useradd --system --gid va-watchdog-web --home-dir /nonexistent --shell /usr/sbin/nologin va-watchdog-web
install -d -m 0755 /usr/local/lib/va-watchdog
install -o root -g root -m 0755 "$APP_DIR/scripts/web_action_helper.py" /usr/local/lib/va-watchdog/web-action-helper.py
install -d -m 0755 /etc/sudoers.d
policy="$(mktemp)"
trap 'rm -f "$policy"' EXIT
printf '%s\n' 'va-watchdog-web ALL=(root) NOPASSWD: /usr/local/lib/va-watchdog/web-action-helper.py ""' > "$policy"
visudo -cf "$policy"
install -o root -g root -m 0440 "$policy" /etc/sudoers.d/va-watchdog-web
# The helper must never import a package writable by its unprivileged caller.
chown -R root:root "$APP_DIR"
chmod -R go-w "$APP_DIR"
install -d -o root -g va-watchdog-web -m 2750 "$CONFIG_DIR" "$DATA_DIR"
chgrp -R va-watchdog-web "$CONFIG_DIR" "$DATA_DIR"
chmod -R g+rX "$CONFIG_DIR" "$DATA_DIR"
find "$CONFIG_DIR" "$DATA_DIR" -type d -exec chmod g+s {} +
python3 - "$CONFIG_DIR/config.json" <<'PY'
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

path = Path(sys.argv[1])
if path.exists():
    original = path.read_text(encoding="utf-8")
    config = json.loads(original)
    recovery = config.setdefault("recovery", {})
    recovery["allow_reboot"] = False
    recovery.pop("critical_grace_seconds", None)
    if isinstance(recovery.get("consolidated_policy"), dict):
        recovery["consolidated_policy"].pop("restart_network_before_reboot", None)
    if config != json.loads(original):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        shutil.copy2(path, path.with_name(path.name + ".pre-hardening-" + stamp + ".bak"))
        temporary = path.with_suffix(".hardening.tmp")
        temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
PY
install -d -o va-watchdog-web -g va-watchdog-web -m 0750 /var/lib/va-watchdog-anpr
chown -R va-watchdog-web:va-watchdog-web /var/lib/va-watchdog-anpr
