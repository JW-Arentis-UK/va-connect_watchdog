from __future__ import annotations

import os
import time
from pathlib import Path

from .common import CheckResult


class ProcessMonitor:
    def __init__(self):
        self.pid = os.getpid()
        self.previous_cpu_ticks = None
        self.previous_time = None
        self.cpu_high_since = None
        self.memory_high_since = None

    def sample(self, cfg: dict) -> CheckResult:
        settings = cfg.get("process_monitor", {}) if isinstance(cfg.get("process_monitor", {}), dict) else {}
        if not settings.get("enabled", True):
            return CheckResult("watchdog_process", "healthy", "Watchdog process monitoring disabled", {"enabled": False}, False)

        now = time.monotonic()
        cpu_ticks = self._cpu_ticks()
        cpu_percent = None
        if cpu_ticks is not None and self.previous_cpu_ticks is not None and self.previous_time is not None:
            elapsed = max(0.001, now - self.previous_time)
            ticks_per_second = os.sysconf("SC_CLK_TCK")
            cpu_percent = round(max(0.0, (cpu_ticks - self.previous_cpu_ticks) / ticks_per_second / elapsed * 100), 1)
        self.previous_cpu_ticks = cpu_ticks
        self.previous_time = now

        memory_mb = self._memory_mb()
        uptime_seconds = self._uptime_seconds()
        cpu_warning = float(settings.get("cpu_warning_percent", 25) or 25)
        cpu_critical = float(settings.get("cpu_critical_percent", 75) or 75)
        memory_warning = float(settings.get("memory_warning_mb", 100) or 100)
        memory_critical = float(settings.get("memory_critical_mb", 200) or 200)
        sustained = max(30, int(settings.get("sustained_seconds", 300) or 300))

        if cpu_percent is not None and cpu_percent >= cpu_warning:
            self.cpu_high_since = self.cpu_high_since or now
        else:
            self.cpu_high_since = None
        if memory_mb is not None and memory_mb >= memory_warning:
            self.memory_high_since = self.memory_high_since or now
        else:
            self.memory_high_since = None

        cpu_high_for = round(now - self.cpu_high_since, 1) if self.cpu_high_since else 0
        memory_high_for = round(now - self.memory_high_since, 1) if self.memory_high_since else 0
        sustained_cpu = cpu_high_for >= sustained and (cpu_percent or 0) >= cpu_critical
        sustained_memory = memory_high_for >= sustained and (memory_mb or 0) >= memory_critical
        if sustained_cpu or sustained_memory:
            state = "critical"
            message = "Watchdog process resource usage remains high"
        elif self.cpu_high_since or self.memory_high_since:
            state = "warning"
            message = "Watchdog process resource usage is above the warning threshold"
        else:
            state = "healthy"
            message = "Watchdog process resource usage is normal"

        value = {
            "enabled": True,
            "pid": self.pid,
            "cpu_percent": cpu_percent,
            "memory_mb": memory_mb,
            "uptime_seconds": uptime_seconds,
            "cpu_warning_percent": cpu_warning,
            "cpu_critical_percent": cpu_critical,
            "memory_warning_mb": memory_warning,
            "memory_critical_mb": memory_critical,
            "sustained_seconds": sustained,
            "cpu_high_for_seconds": cpu_high_for,
            "memory_high_for_seconds": memory_high_for,
            "state": state,
            "message": message,
        }
        # This check is deliberately non-critical to the hardware feed. If the
        # process is unhealthy, systemd must enforce the restart boundary.
        return CheckResult("watchdog_process", state, message, value, False)

    def _cpu_ticks(self):
        try:
            fields = Path(f"/proc/{self.pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
            return int(fields[11]) + int(fields[12])
        except (OSError, IndexError, ValueError):
            return None

    def _memory_mb(self):
        try:
            for line in Path(f"/proc/{self.pid}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
        except (OSError, IndexError, ValueError):
            pass
        return None

    def _uptime_seconds(self):
        try:
            fields = Path(f"/proc/{self.pid}/stat").read_text(encoding="utf-8").rsplit(") ", 1)[1].split()
            start_ticks = int(fields[19])
            clock_ticks = os.sysconf("SC_CLK_TCK")
            system_uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
            return round(max(0.0, system_uptime - start_ticks / clock_ticks), 1)
        except (OSError, IndexError, ValueError):
            return None


_PROCESS_MONITOR = ProcessMonitor()


def check_watchdog_process(cfg: dict) -> CheckResult:
    return _PROCESS_MONITOR.sample(cfg)
