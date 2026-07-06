from __future__ import annotations

import subprocess
from .common import CheckResult

def _is_active(name):
    try:
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
        return r.stdout.strip() or "unknown"
    except Exception:
        return "unknown"

def _restart_count(name):
    try:
        r = subprocess.run(["systemctl", "show", name, "-p", "NRestarts"], capture_output=True, text=True, timeout=5)
        if "=" in r.stdout:
            return int(r.stdout.strip().split("=", 1)[1] or 0)
    except Exception:
        pass
    return None

def check_services(cfg):
    checks = []
    for svc in cfg["services"]:
        name = svc["name"]
        active = _is_active(name)
        restarts = _restart_count(name)
        value = {"active": active, "restarts": restarts}
        if active == "active":
            checks.append(CheckResult(name, "healthy", "Service active", value, svc.get("critical", False)))
        else:
            state = "critical" if svc.get("critical", False) else "degraded"
            checks.append(CheckResult(name, state, f"Service is {active}", value, svc.get("critical", False)))
    return checks
