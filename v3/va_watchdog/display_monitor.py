"""Optional, bounded recovery for a configured graphical desktop."""
from __future__ import annotations

import subprocess
import time

from .common import CheckResult

MANAGERS = ("gdm3.service", "gdm.service", "lightdm.service", "sddm.service")
WAYLAND_PROCESSES = ("labwc", "wayfire", "gnome-shell", "weston", "kwin_wayland")


def command_ok(*args: str, timeout: int = 5) -> bool:
    try:
        return subprocess.run(args, capture_output=True, timeout=timeout, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def manager_for(cfg: dict) -> str | None:
    selected = str(cfg.get("manager") or "").strip()
    if selected:
        if selected not in MANAGERS:
            raise ValueError("display_monitor.manager must name a supported display-manager service")
        return selected
    for name in MANAGERS:
        if command_ok("systemctl", "is-enabled", "--quiet", name) or command_ok("systemctl", "is-active", "--quiet", name):
            return name
    return None


class DisplayMonitor:
    def __init__(self, cfg: dict, event_log=None):
        self.settings = cfg.get("display_monitor", {}) or {}
        self.enabled = bool(self.settings.get("enabled", False))
        self.event_log = event_log
        self.manager = manager_for(self.settings) if self.enabled else None
        self.interval = max(10, int(self.settings.get("check_interval_seconds", 30)))
        self.grace = max(0, int(self.settings.get("startup_grace_seconds", 90)))
        self.cooldown = max(60, int(self.settings.get("restart_cooldown_seconds", 300)))
        self.max_restarts = max(1, int(self.settings.get("max_restarts_per_hour", 3)))
        self.expect_x11 = bool(self.settings.get("expect_x11", True))
        self.started = time.monotonic()
        self.last_probe = 0.0
        self.last_restart = float("-inf")
        self.failures = 0
        self.restart_times: list[float] = []
        self.cached: CheckResult | None = None

    def poll(self) -> CheckResult | None:
        if not self.enabled:
            return None
        now = time.monotonic()
        if self.cached is not None and now - self.last_probe < self.interval:
            return self.cached
        self.last_probe = now
        if not self.manager:
            self.cached = CheckResult("display_session", "warning", "No supported display manager is configured", critical=False)
            return self.cached

        active = command_ok("systemctl", "is-active", "--quiet", self.manager)
        processes = ("Xorg",) if self.expect_x11 else ("Xorg",) + WAYLAND_PROCESSES
        session = any(command_ok("pgrep", "-x", process) for process in processes)
        value = {"manager": self.manager, "manager_active": active, "graphical_session_running": session,
                 "expected": "X11" if self.expect_x11 else "X11 or Wayland"}
        if active and session:
            self.failures = 0
            self.cached = CheckResult("display_session", "healthy", f"{self.manager} and graphical session running", value, False)
            return self.cached

        self.failures += 1
        reason = f"{self.manager} inactive" if not active else "Graphical session process missing"
        message = reason
        self.restart_times = [stamp for stamp in self.restart_times if now - stamp < 3600]
        ready = now - self.started >= self.grace and self.failures >= 2
        allowed = now - self.last_restart >= self.cooldown and len(self.restart_times) < self.max_restarts
        if ready and allowed:
            self.last_restart = now
            self.restart_times.append(now)
            success = command_ok("systemctl", "restart", self.manager, timeout=20)
            message = f"{reason}; restarted {self.manager}" if success else f"{reason}; restart failed"
            if self.event_log is not None:
                self.event_log.add("warning", "display", message, value)
        elif ready and len(self.restart_times) >= self.max_restarts:
            message = f"{reason}; hourly restart limit reached"
        self.cached = CheckResult("display_session", "warning", message, value, False)
        return self.cached
