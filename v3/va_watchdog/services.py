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

def _runtime_stats(name):
    try:
        result = subprocess.run(
            ["systemctl", "show", name, "-p", "MainPID"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pid = result.stdout.strip().split("=", 1)[-1] if "=" in result.stdout else "0"
        if not pid or pid == "0":
            return {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}
        ps = subprocess.run(
            ["ps", "-p", pid, "-o", "%cpu=,rss=,etimes="],
            capture_output=True,
            text=True,
            timeout=5,
        )
        parts = ps.stdout.split()
        if len(parts) < 3:
            return {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}
        return {
            "cpu_percent": float(parts[0]),
            "memory_mb": round(int(parts[1]) / 1024, 1),
            "uptime_seconds": int(parts[2]),
        }
    except (OSError, ValueError, subprocess.SubprocessError):
        return {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}

def check_services(cfg):
    checks = []
    for svc in cfg["services"]:
        name = svc["name"]
        active = _is_active(name)
        restarts = _restart_count(name)
        value = {"active": active, "restarts": restarts, **_runtime_stats(name)}
        if active == "active":
            checks.append(CheckResult(name, "healthy", "Service active", value, svc.get("critical", False)))
        else:
            state = "critical" if svc.get("critical", False) else "degraded"
            checks.append(CheckResult(name, state, f"Service is {active}", value, svc.get("critical", False)))
    return checks
