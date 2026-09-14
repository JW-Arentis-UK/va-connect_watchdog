from __future__ import annotations

import os
import time
import subprocess
from pathlib import Path
from .common import CheckResult

_CPU_SAMPLES = {}

def _service_properties(name):
    try:
        result = subprocess.run(
            ["systemctl", "show", name, "-p", "ActiveState", "-p", "NRestarts", "-p", "MainPID"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        properties = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        active = properties.get("ActiveState") or "unknown"
        try:
            restarts = int(properties.get("NRestarts") or 0)
        except ValueError:
            restarts = None
        pid = properties.get("MainPID") or "0"
        if not pid or pid == "0":
            return active, restarts, {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}
        now = time.monotonic()
        cpu_ticks = None
        start_ticks = None
        try:
            fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
            cpu_ticks = int(fields[11]) + int(fields[12])
            start_ticks = int(fields[19])
        except (OSError, IndexError, ValueError):
            pass
        rss_kb = None
        try:
            for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    break
        except (OSError, ValueError, IndexError):
            pass
        previous = _CPU_SAMPLES.get(name)
        cpu_percent = None
        if cpu_ticks is not None and previous and previous[0] == pid:
            elapsed = max(0.001, now - previous[2])
            cpu_percent = round(max(0.0, (cpu_ticks - previous[1]) / os.sysconf("SC_CLK_TCK") / elapsed * 100), 1)
        if cpu_ticks is not None:
            _CPU_SAMPLES[name] = (pid, cpu_ticks, now)
        system_cpu_percent = round(cpu_percent / max(1, os.cpu_count() or 1), 1) if cpu_percent is not None else None
        uptime_seconds = None
        if start_ticks is not None:
            try:
                system_uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
                uptime_seconds = max(0, int(system_uptime - start_ticks / os.sysconf("SC_CLK_TCK")))
            except (OSError, ValueError, IndexError):
                pass
        return active, restarts, {
            "cpu_percent": cpu_percent,
            "cpu_system_percent": system_cpu_percent,
            "memory_mb": round(rss_kb / 1024, 1) if rss_kb is not None else None,
            "uptime_seconds": uptime_seconds,
        }
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unknown", None, {"cpu_percent": None, "memory_mb": None, "uptime_seconds": None}


def _runtime_stats(name):
    """Compatibility helper used by the manual service-details page."""
    return _service_properties(name)[2]

def check_services(cfg):
    checks = []
    for svc in cfg["services"]:
        name = svc["name"]
        active, restarts, runtime = _service_properties(name)
        value = {"active": active, "restarts": restarts, **runtime}
        if active == "active":
            checks.append(CheckResult(name, "healthy", "Service active", value, svc.get("critical", False)))
        else:
            state = "critical" if svc.get("critical", False) else "degraded"
            checks.append(CheckResult(name, state, f"Service is {active}", value, svc.get("critical", False)))
    return checks
