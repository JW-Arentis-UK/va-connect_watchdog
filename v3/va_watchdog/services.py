from __future__ import annotations

import os
import time
import subprocess
from pathlib import Path
from .common import CheckResult

_CPU_SAMPLES = {}

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
        now = time.monotonic()
        cpu_ticks = None
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
            cpu_ticks = int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            pass
        ps = subprocess.run(
            ["ps", "-p", pid, "-o", "rss=,etimes="],
            capture_output=True,
            text=True,
            timeout=5,
        )
        parts = ps.stdout.split()
        if len(parts) < 2:
            return {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}
        previous = _CPU_SAMPLES.get(name)
        cpu_percent = None
        if cpu_ticks is not None and previous and previous[0] == pid:
            elapsed = max(0.001, now - previous[2])
            cpu_percent = round(max(0.0, (cpu_ticks - previous[1]) / os.sysconf("SC_CLK_TCK") / elapsed * 100), 1)
        if cpu_ticks is not None:
            _CPU_SAMPLES[name] = (pid, cpu_ticks, now)
        return {
            "cpu_percent": cpu_percent,
            "memory_mb": round(int(parts[0]) / 1024, 1),
            "uptime_seconds": int(parts[1]),
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
